#!/usr/bin/env node
// Latchkey client. Dependency-free: Node's http + crypto only.
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const child_process = require('child_process');

const PROTOCOL = 1;
const AAD = Buffer.from('LATCHKEY/1', 'utf8');
const PAIR_AAD_PREFIX = 'LATCHKEY/PAIR/1|';
const CLIENT_VERSION = '1.3.0-C';
const CREDENTIALS_VERSION = 1;
const DEFAULT_URL = 'http://127.0.0.1:39401';
const DEFAULT_CHUNK = 1024 * 1024;
const MAX_CHUNK = 4 * 1024 * 1024;
const MAX_RESPONSE = 32 * 1024 * 1024;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;

export function decodeKey(text) {
  if (!text) throw new Error('missing key (use --key, LATCHKEY_KEY, or run: latchkey pair --clipboard)');
  const cleaned = String(text).trim();
  if (!/^[A-Za-z0-9_-]{43}$/.test(cleaned)) {
    throw new Error('key must be exactly 43 base64url characters');
  }
  const key = Buffer.from(cleaned, 'base64url');
  if (key.length !== 32 || key.toString('base64url') !== cleaned) {
    throw new Error('key is not canonical 32-byte base64url');
  }
  return key;
}

function aadBuffer(aad) {
  if (aad == null) return AAD;
  return Buffer.isBuffer(aad) ? aad : Buffer.from(String(aad), 'utf8');
}

export function encryptPayload(key, value, aad = AAD) {
  const plaintext = Buffer.from(JSON.stringify(value), 'utf8');
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aadBuffer(aad));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]);
}

export function decryptPayload(key, blob, aad = AAD) {
  if (!Buffer.isBuffer(blob) || blob.length < 28) {
    throw new Error('encrypted response is too short');
  }
  const nonce = blob.subarray(0, 12);
  const tag = blob.subarray(blob.length - 16);
  const ciphertext = blob.subarray(12, blob.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAAD(aadBuffer(aad));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export class RpcFailure extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

export async function rpcCall({ key, host, port, aad, clientId }, op, params = {}, timeout = 30000) {
  const request = {
    v: PROTOCOL,
    id: crypto.randomUUID(),
    ts: Date.now(),
    op,
    ...params,
  };
  const body = encryptPayload(key, request, aad);
  const data = await postRaw({ host, port, body, timeout, clientId });
  const response = JSON.parse(decryptPayload(key, data, aad).toString('utf8'));
  if (!response || typeof response !== 'object') {
    throw new Error('server response is not an object');
  }
  if (response.id !== request.id) {
    throw new Error('server response id does not match the request');
  }
  if (typeof response.serverTime !== 'number'
      || Math.abs(Date.now() - response.serverTime) > MAX_CLOCK_SKEW_MS) {
    throw new Error('server response timestamp is outside the allowed window');
  }
  if (!response.ok) {
    throw new RpcFailure(response.code || 'ERROR', response.error || 'request failed');
  }
  return response;
}

function postRaw({ host, port, body, timeout, clientId }) {
  return new Promise((resolve, reject) => {
    const headers = {
      'Content-Type': 'application/octet-stream',
      'Content-Length': body.length,
      'Connection': 'close',
    };
    if (clientId) {
      headers['X-Latchkey-Client'] = clientId;
    }
    const req = http.request({
      host,
      port,
      path: '/rpc',
      method: 'POST',
      agent: false,
      headers,
    }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_RESPONSE) {
          res.destroy(new Error('server response is too large'));
          return;
        }
        chunks.push(chunk);
      });
      res.on('error', reject);
      res.on('end', () => {
        const data = Buffer.concat(chunks);
        if (res.statusCode === 401) {
          reject(new Error('unauthorized: the key does not match the app; '
            + 'if it was revoked or app data was cleared, pair again'));
          return;
        }
        if (res.statusCode !== 200) {
          const text = data.toString('utf8').slice(0, 200);
          reject(new Error(`server returned HTTP ${res.statusCode}${text ? ': ' + text : ''}`));
          return;
        }
        resolve(data);
      });
    });
    req.setTimeout(timeout, () => {
      req.destroy(new Error('request timed out'));
    });
    req.on('error', (err) => {
      if (err.code === 'ECONNREFUSED') {
        reject(new Error('cannot connect to 127.0.0.1:' + port
          + ' — is the Latchkey server running?'));
      } else {
        reject(err);
      }
    });
    req.end(body);
  });
}

function getHealth(host, port) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host, port, path: '/health', agent: false }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size > 64 * 1024) {
          res.destroy(new Error('health response is too large'));
          return;
        }
        chunks.push(chunk);
      });
      res.on('error', reject);
      res.on('end', () => {
        if (res.statusCode !== 200) {
          reject(new Error(`health returned HTTP ${res.statusCode}`));
          return;
        }
        try {
          const health = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (!health || health.app !== 'latchkey' || health.ok !== true) {
            reject(new Error('health response is not a Latchkey health response'));
            return;
          }
          resolve(health);
        } catch (err) {
          reject(new Error('health response was not JSON'));
        }
      });
    });
    req.setTimeout(10000, () => req.destroy(new Error('health request timed out')));
    req.on('error', (err) => {
      if (err.code === 'ECONNREFUSED') {
        reject(new Error('cannot connect to 127.0.0.1:' + port
          + ' — is the Latchkey server running?'));
      } else {
        reject(err);
      }
    });
  });
}

export function parseServerUrl(text) {
  let url;
  try {
    url = new URL(text || DEFAULT_URL);
  } catch (err) {
    throw new Error('invalid server URL');
  }
  if (url.protocol !== 'http:') {
    throw new Error('only http:// loopback URLs are supported');
  }
  if (url.username || url.password || url.search || url.hash
      || (url.pathname && url.pathname !== '/')) {
    throw new Error('server URL must not contain credentials, a path, query, or fragment');
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (hostname !== '127.0.0.1' && hostname !== 'localhost') {
    throw new Error('only 127.0.0.1 or localhost is allowed');
  }
  const port = Number(url.port || 39401);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('server port is invalid');
  }
  return { host: '127.0.0.1', port };
}

export function credentialsPath() {
  if (process.env.LATCHKEY_CREDENTIALS) {
    return path.resolve(process.env.LATCHKEY_CREDENTIALS);
  }
  const base = process.env.LATCHKEY_CONFIG_HOME
    || process.env.XDG_CONFIG_HOME
    || path.join(os.homedir(), '.config');
  return path.join(base, 'latchkey', 'credentials.json');
}

export function loadCredentials(file = credentialsPath()) {
  let text;
  try {
    const info = fs.lstatSync(file);
    if (info.isSymbolicLink() || !info.isFile()) {
      throw new Error('credentials path is not a regular file');
    }
    if ((info.mode & 0o077) !== 0) {
      process.stderr.write(`warning: ${safe(file)} is readable by other users; chmod 600 it\n`);
    }
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    if (err && err.code === 'ENOENT') return null;
    throw err;
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch (err) {
    throw new Error('credentials file is not valid JSON');
  }
  if (!value || typeof value !== 'object' || value.version !== CREDENTIALS_VERSION) {
    throw new Error('credentials file has an unsupported format');
  }
  if (typeof value.clientId !== 'string' || !/^[a-f0-9]{16,64}$/.test(value.clientId)) {
    throw new Error('credentials file has an invalid client id');
  }
  const key = decodeKey(value.key);
  const url = parseServerUrl(value.url);
  const stored = {
    version: CREDENTIALS_VERSION,
    url: `http://127.0.0.1:${url.port}`,
    clientId: value.clientId,
    key: key.toString('base64url'),
    name: typeof value.name === 'string' ? value.name.slice(0, 80) : '',
    hostId: typeof value.hostId === 'string' ? value.hostId : '',
    fingerprint: typeof value.fingerprint === 'string' ? value.fingerprint : '',
    pairedAt: typeof value.pairedAt === 'string' ? value.pairedAt : '',
    path: file,
  };
  key.fill(0);
  return stored;
}

function saveCredentials(value, file = credentialsPath()) {
  const directory = path.dirname(file);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  try { fs.chmodSync(directory, 0o700); } catch (ignored) { /* windows */ }
  const temp = `${file}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
  const body = JSON.stringify(value, null, 2) + '\n';
  let fd;
  try {
    fd = fs.openSync(temp, 'wx', 0o600);
    fs.writeFileSync(fd, body, { encoding: 'utf8' });
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(temp, file);
  } catch (err) {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch (ignored) { /* ignore */ }
    }
    try { fs.unlinkSync(temp); } catch (ignored) { /* ignore */ }
    throw err;
  }
  try { fs.chmodSync(file, 0o600); } catch (ignored) { /* windows */ }
}

export function parsePairLink(text) {
  const raw = String(text == null ? '' : text).trim();
  if (!/^latchkey:\/\/pair\?/i.test(raw)) {
    throw new Error('clipboard does not contain a Latchkey pairing link');
  }
  let url;
  try {
    url = new URL(raw);
  } catch (err) {
    throw new Error('pairing link is not a valid URL');
  }
  if (url.protocol !== 'latchkey:' || url.hostname !== 'pair') {
    throw new Error('pairing link is not a Latchkey pairing link');
  }
  const query = url.searchParams;
  if (query.get('scope') !== 'loopback') {
    throw new Error('this client only supports loopback pairing links');
  }
  if (query.get('v') !== '1') {
    throw new Error('unsupported pairing link version');
  }
  const host = (query.get('host') || '').toLowerCase();
  if (host !== '127.0.0.1' && host !== 'localhost') {
    throw new Error('pairing link is not for loopback');
  }
  const port = Number(query.get('port'));
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('pairing link has an invalid port');
  }
  const token = query.get('tok') || '';
  const tokenKey = decodeKey(token);
  tokenKey.fill(0);
  const hostId = query.get('id') || '';
  if (!/^[a-f0-9]{16,64}$/.test(hostId)) {
    throw new Error('pairing link has an invalid host id');
  }
  const expiresAt = Number(query.get('exp'));
  if (!Number.isFinite(expiresAt) || expiresAt <= 0) {
    throw new Error('pairing link has an invalid expiry');
  }
  const now = Date.now();
  if (expiresAt <= now) {
    throw new Error('pairing link expired; tap Pair assistant again');
  }
  if (expiresAt > now + 10 * 60 * 1000) {
    throw new Error('pairing link expiry is unreasonably far in the future');
  }
  let name = query.get('name') || 'Android device';
  name = name.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 80);
  if (!name) name = 'Android device';
  return {
    host: '127.0.0.1',
    port,
    token,
    hostId,
    expiresAt,
    name,
    appFingerprint: query.get('fp') || '',
    link: raw,
  };
}

export function normalizeClipboardText(raw) {
  let text = String(raw == null ? '' : raw);
  const trimmed = text.trim();
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed.result === 'string' && parsed.result.length > 0) {
        text = parsed.result;
      } else if (parsed && typeof parsed.output === 'string' && parsed.output.length > 0) {
        text = parsed.output;
      }
    } catch (ignored) {
      // Not a wrapper; use the raw text.
    }
  }
  return text;
}

function readClipboard() {
  const attempts = [
    ['termux-clipboard-get', []],
    ['wl-paste', ['--no-newline']],
    ['xclip', ['-selection', 'clipboard', '-o']],
    ['xsel', ['--clipboard', '--output']],
  ];
  let foundTool = false;
  for (const [command, args] of attempts) {
    const result = child_process.spawnSync(command, args, {
      encoding: 'utf8',
      timeout: 5000,
      maxBuffer: 64 * 1024,
    });
    if (result.error && result.error.code === 'ENOENT') continue;
    foundTool = true;
    if (result.error || result.status !== 0) continue;
    return normalizeClipboardText(result.stdout);
  }
  if (!foundTool) {
    throw new Error('no clipboard tool found (install Termux:API and use termux-clipboard-get)');
  }
  throw new Error('could not read the clipboard');
}

async function waitForPairLink(seconds) {
  const deadline = Date.now() + seconds * 1000;
  let lastSeen = '';
  while (Date.now() < deadline) {
    let text = '';
    try {
      text = String(readClipboard() || '').trim();
    } catch (ignored) {
      /* retry */
    }
    if (text && text !== lastSeen) {
      lastSeen = text;
      try {
        parsePairLink(text);
        return text;
      } catch (err) {
        if (!/expired/i.test(String(err && err.message))) {
          /* Not a valid fresh link yet. */
        }
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error('timed out waiting for a pairing link; tap Pair assistant again');
}

function clearClipboard() {
  try {
    child_process.spawnSync('termux-clipboard-set', [''], {
      timeout: 3000,
      stdio: 'ignore',
    });
  } catch (ignored) {
    /* best effort */
  }
}

function postPair({ host, port, body, timeout = 15000 }) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host,
      port,
      path: '/pair',
      method: 'POST',
      agent: false,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': body.length,
        'Connection': 'close',
      },
    }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size > 64 * 1024) {
          res.destroy(new Error('pairing response is too large'));
          return;
        }
        chunks.push(chunk);
      });
      res.on('error', reject);
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          text: Buffer.concat(chunks).toString('utf8'),
        });
      });
    });
    req.setTimeout(timeout, () => req.destroy(new Error('pairing request timed out')));
    req.on('error', (err) => {
      if (err.code === 'ECONNREFUSED') {
        reject(new Error('cannot connect to 127.0.0.1:' + port
          + ' — start the Latchkey server and create a new link'));
      } else {
        reject(err);
      }
    });
    req.end(body);
  });
}

function shortFingerprint(key) {
  return crypto.createHash('sha256').update(key).digest()
    .subarray(0, 8).toString('hex').toUpperCase();
}

export async function pairWithLink(link, options = {}) {
  const parsed = parsePairLink(link);
  const clientId = crypto.randomBytes(16).toString('hex');
  const clientName = (options.name || `Assistant on ${os.hostname()}`)
    .replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 80)
    || 'Assistant';
  const request = {
    v: 1,
    token: parsed.token,
    client: {
      id: clientId,
      name: clientName,
      platform: process.platform,
    },
  };
  const body = Buffer.from(JSON.stringify(request), 'utf8');
  const response = await postPair({ host: parsed.host, port: parsed.port, body });
  let payload;
  try {
    payload = JSON.parse(response.text);
  } catch (err) {
    throw new Error('pairing server returned invalid JSON');
  }
  if (response.status !== 200 || !payload || payload.ok !== true) {
    const code = payload && payload.code ? safe(payload.code) : 'HTTP_' + response.status;
    const message = payload && payload.error ? safe(payload.error) : 'pairing failed';
    throw new Error(`pairing failed (${code}): ${message}`);
  }
  if (payload.v !== 1 || payload.clientId !== clientId) {
    throw new Error('pairing response does not match this client');
  }
  if (typeof payload.key !== 'string' || payload.key.length > 512) {
    throw new Error('pairing response is missing the client key');
  }

  const pairKey = crypto.createHash('sha256').update(parsed.token, 'utf8').digest();
  let clientKey;
  try {
    clientKey = decryptPayload(
      pairKey,
      Buffer.from(payload.key, 'base64url'),
      Buffer.from(PAIR_AAD_PREFIX + clientId, 'utf8'));
  } finally {
    pairKey.fill(0);
  }
  if (clientKey.length !== 32) {
    clientKey.fill(0);
    throw new Error('pairing response key has the wrong size');
  }
  const fingerprint = shortFingerprint(clientKey);
  if (payload.fingerprint && payload.fingerprint !== fingerprint) {
    clientKey.fill(0);
    throw new Error('pairing response fingerprint does not match the key');
  }

  const keyText = clientKey.toString('base64url');
  const credentials = {
    version: CREDENTIALS_VERSION,
    url: `http://127.0.0.1:${parsed.port}`,
    clientId,
    key: keyText,
    name: parsed.name,
    hostId: parsed.hostId,
    fingerprint,
    pairedAt: new Date().toISOString(),
  };
  const file = options.credentialsFile || credentialsPath();
  saveCredentials(credentials, file);

  const context = {
    key: clientKey,
    host: parsed.host,
    port: parsed.port,
    clientId,
    aad: Buffer.from('LATCHKEY/1|client:' + clientId, 'utf8'),
  };
  let verified = false;
  let verificationError = null;
  try {
    await rpcCall(context, 'ping', {}, 10000);
    verified = true;
  } catch (err) {
    verificationError = err && err.message ? err.message : String(err);
  } finally {
    clientKey.fill(0);
  }
  return {
    credentials: {
      url: credentials.url,
      clientId,
      name: parsed.name,
      hostId: parsed.hostId,
      fingerprint,
      path: file,
    },
    verified,
    verificationError,
  };
}

function takeOption(args, names, defaultValue = undefined) {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    for (const name of names) {
      if (arg === name) {
        if (i + 1 >= args.length) throw new Error(name + ' needs a value');
        const value = args[i + 1];
        args.splice(i, 2);
        return value;
      }
      if (arg.startsWith(name + '=')) {
        const value = arg.slice(name.length + 1);
        args.splice(i, 1);
        return value;
      }
    }
  }
  return defaultValue;
}

function takeFlag(args, names) {
  for (let i = 0; i < args.length; i++) {
    if (names.includes(args[i])) {
      args.splice(i, 1);
      return true;
    }
  }
  return false;
}

function requirePositional(args, count, usage) {
  if (args.length < count) throw new Error('usage: ' + usage);
  return args;
}

function writeAll(fd, data) {
  let offset = 0;
  while (offset < data.length) {
    const written = fs.writeSync(fd, data, offset, data.length - offset);
    if (written <= 0) throw new Error('short write to output file');
    offset += written;
  }
}

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  let value = bytes / 1024;
  if (value < 1024) return value.toFixed(1) + ' KiB';
  value /= 1024;
  if (value < 1024) return value.toFixed(1) + ' MiB';
  value /= 1024;
  return value.toFixed(2) + ' GiB';
}

function formatDate(ms) {
  if (!ms) return '-';
  const date = new Date(ms);
  const pad = (n) => String(n).padStart(2, '0');
  return date.getFullYear() + '-' + pad(date.getMonth() + 1) + '-' + pad(date.getDate())
    + ' ' + pad(date.getHours()) + ':' + pad(date.getMinutes());
}

function formatDuration(ms) {
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return seconds + 's';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return minutes + 'm ' + (seconds % 60) + 's';
  const hours = Math.floor(minutes / 60);
  return hours + 'h ' + (minutes % 60) + 'm';
}

function safe(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(
    /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, '?');
}

function formatLogEntry(entry) {
  const date = new Date(Number(entry.t) || 0).toISOString().replace('T', ' ').replace('Z', '');
  const level = safe(entry.level || '').padEnd(5);
  const cat = safe(entry.cat || '');
  const event = safe(entry.event || '');
  const message = safe(entry.msg || '');
  const data = entry.data ? ' ' + safe(JSON.stringify(entry.data)) : '';
  return `${date} ${level} ${cat} ${event} ${message}${data}`;
}

function typeChar(entry) {
  if (entry.type === 'dir') return 'd';
  if (entry.type === 'link') return 'l';
  if (entry.type === 'file') return 'f';
  return '?';
}

function printJson(value) {
  process.stdout.write(JSON.stringify(value, null, 2) + '\n');
}

function chunkSizeFrom(args) {
  const raw = takeOption(args, ['--chunk-size']);
  const value = raw ? Number(raw) : DEFAULT_CHUNK;
  if (!Number.isFinite(value) || value <= 0) throw new Error('bad --chunk-size');
  return Math.min(MAX_CHUNK, Math.max(64 * 1024, Math.floor(value)));
}

async function commandHealth(ctx, args) {
  const health = await getHealth(ctx.host, ctx.port);
  if (ctx.json) {
    printJson(health);
    return;
  }
  process.stdout.write(`ok • latchkey ${safe(health.version)} • 127.0.0.1:${safe(health.port)}`
    + ` • up ${formatDuration(health.uptimeMs)} • ${safe(health.requests)} requests\n`);
}

async function commandPing(ctx, args) {
  const result = await rpcCall(ctx, 'ping');
  if (ctx.json) {
    printJson(result);
    return;
  }
  process.stdout.write(`pong • latchkey ${safe(result.version)} • 127.0.0.1:${safe(result.port)}`
    + ` • up ${formatDuration(result.uptimeMs)} • key ${safe(result.keyFingerprint)}\n`);
}

async function commandInfo(ctx, args) {
  const result = await rpcCall(ctx, 'info');
  if (ctx.json) {
    printJson(result);
    return;
  }
  const storage = result.storage || {};
  const access = result.access || {};
  const server = result.server || {};
  const device = result.device || {};
  process.stdout.write(`latchkey   ${safe(result.versionName)} (${safe(result.versionCode)})\n`);
  process.stdout.write(`device     ${safe(device.manufacturer || '?')} ${safe(device.model || '?')}`
    + ` • Android ${safe(device.release || '?')} (SDK ${safe(device.sdk || '?')})\n`);
  process.stdout.write(`storage    ${safe(storage.path || '?')} • ${formatSize(storage.totalBytes || 0)} total`
    + ` • ${formatSize(storage.availableBytes || 0)} free\n`);
  process.stdout.write(`access     all files ${access.allFiles ? 'yes' : 'NO'}`
    + ` • read ${access.read ? 'yes' : 'no'} • write ${access.write ? 'yes' : 'no'}\n`);
  process.stdout.write(`server     up ${formatDuration(server.uptimeMs || 0)}`
    + ` • ${server.requests || 0} requests • in ${formatSize(server.bytesIn || 0)}`
    + ` • out ${formatSize(server.bytesOut || 0)}\n`);
  process.stdout.write(`key        SHA-256 ${safe(server.keyFingerprint || '?')}\n`);
  for (const root of result.roots || []) {
    process.stdout.write(`root       ${safe(root.label).padEnd(13)} ${safe(root.path)}\n`);
  }
}

async function commandLs(ctx, args) {
  requirePositional(args, 1, 'latchkey ls <path> [--limit N] [--offset N]');
  const target = args[0];
  const limit = Number(takeOption(args, ['--limit'], '2000'));
  const offset = Number(takeOption(args, ['--offset'], '0'));
  const result = await rpcCall(ctx, 'list', { path: target, limit, offset });
  if (ctx.json) {
    printJson(result);
    return;
  }
  for (const entry of result.entries) {
    const suffix = entry.type === 'dir' ? '/' : (entry.type === 'link' ? '@' : '');
    process.stdout.write(`${typeChar(entry)}  ${formatDate(entry.mtime)}  `
      + `${formatSize(entry.size).padStart(10)}  ${safe(entry.name)}${suffix}\n`);
  }
  if (result.truncated) {
    process.stderr.write(`... ${result.total - result.offset - result.entries.length} more`
      + ` (use --offset ${result.offset + result.entries.length})\n`);
  }
}

async function commandStat(ctx, args) {
  requirePositional(args, 1, 'latchkey stat <path>');
  const result = await rpcCall(ctx, 'stat', { path: args[0] });
  if (ctx.json) {
    printJson(result);
    return;
  }
  process.stdout.write(`path      ${safe(result.path)}\n`);
  process.stdout.write(`type      ${safe(result.type)}`
    + `${result.symlink ? ' -> ' + safe(result.target) : ''}\n`);
  process.stdout.write(`size      ${formatSize(result.size)} (${safe(result.size)} bytes)\n`);
  process.stdout.write(`modified  ${formatDate(result.mtime)}\n`);
  process.stdout.write(`mode      read=${result.canRead ? 'yes' : 'no'}`
    + ` write=${result.canWrite ? 'yes' : 'no'}`
    + ` exec=${result.canExecute ? 'yes' : 'no'}\n`);
  if (result.canonical) process.stdout.write(`canonical ${safe(result.canonical)}\n`);
}

async function commandRead(ctx, args, mode = 'read') {
  const output = takeOption(args, ['-o', '--output'], '-');
  const offsetStart = Number(takeOption(args, ['--offset'], '0'));
  const maxLength = takeOption(args, ['--length']);
  const chunkSize = chunkSizeFrom(args);
  const forceStdout = takeFlag(args, ['--force', '--stdout']);
  requirePositional(args, 1, `latchkey ${mode} <path> [-o file]`);
  const target = args[0];

  if (!Number.isInteger(offsetStart) || offsetStart < 0) {
    throw new Error('--offset must be a non-negative integer');
  }
  if (maxLength !== undefined) {
    const value = Number(maxLength);
    if (!Number.isInteger(value) || value < 0) {
      throw new Error('--length must be a non-negative integer');
    }
  }
  const limit = maxLength === undefined ? Infinity : Number(maxLength);

  const toStdout = output === '-';
  if (toStdout && process.stdout.isTTY && !forceStdout) {
    throw new Error('refusing to write binary to a terminal; use -o <file> or --stdout');
  }
  let fd = null;
  let tempOutput = null;
  let completed = false;
  if (!toStdout) {
    tempOutput = path.join(path.dirname(output),
      '.latchkey-part-' + crypto.randomBytes(12).toString('hex'));
    fd = fs.openSync(tempOutput, 'wx', 0o600);
  }
  let offset = offsetStart;
  let remaining = limit;
  let written = 0;
  let totalSize = 0;
  let lastProgress = 0;

  try {
    for (;;) {
      if (remaining <= 0) break;
      const length = Math.min(chunkSize, remaining === Infinity ? chunkSize : remaining);
      const result = await rpcCall(ctx, 'read', {
        path: target,
        offset,
        length,
      });
      totalSize = result.size;
      const data = Buffer.from(result.data || '', 'base64');
      if (data.length > 0) {
        if (toStdout) {
          process.stdout.write(data);
        } else {
          writeAll(fd, data);
        }
        written += data.length;
        remaining -= data.length;
      }
      if (result.eof || data.length === 0) break;
      offset = result.nextOffset;
      if (totalSize > 2 * 1024 * 1024) {
        const now = Date.now();
        if (now - lastProgress > 250) {
          lastProgress = now;
          const percent = totalSize ? Math.floor((offset / totalSize) * 100) : 0;
          process.stderr.write(`\rread ${formatSize(offset)} / ${formatSize(totalSize)} (${percent}%)`);
        }
      }
    }
    if (!toStdout) {
      fs.fsyncSync(fd);
    }
    completed = true;
  } finally {
    if (fd !== null) {
      fs.closeSync(fd);
    }
    if (!toStdout) {
      if (completed) {
        try {
          fs.renameSync(tempOutput, output);
        } catch (err) {
          try { fs.unlinkSync(tempOutput); } catch (ignored) {}
          throw err;
        }
      } else {
        try { fs.unlinkSync(tempOutput); } catch (ignored) {}
      }
    }
    if (totalSize > 2 * 1024 * 1024) process.stderr.write('\n');
  }

  if (ctx.json) {
    printJson({ path: target, written, size: totalSize, output });
  } else if (!toStdout) {
    process.stderr.write(`read ${formatSize(written)} from ${safe(target)} -> ${safe(output)}\n`);
  }
}

async function commandWrite(ctx, args, mode = 'write') {
  const from = takeOption(args, ['-f', '--from']);
  const append = takeFlag(args, ['--append']);
  const noMkdirs = takeFlag(args, ['--no-mkdirs']);
  const chunkSize = chunkSizeFrom(args);
  const forceStdin = takeFlag(args, ['--stdin']);
  requirePositional(args, 1, `latchkey ${mode} <path> (--from file | < data)`);
  const target = args[0];

  if (!from && process.stdin.isTTY && !forceStdin) {
    throw new Error('no input: use --from <file> or pipe data on stdin');
  }
  let fd = 0;
  let total = null;
  if (from) {
    fd = fs.openSync(from, 'r');
    total = fs.fstatSync(fd).size;
  }
  const buffer = Buffer.allocUnsafe(chunkSize);
  let sent = 0;
  let offset = 0;
  let first = true;
  let lastProgress = 0;

  try {
    for (;;) {
      const read = fs.readSync(fd, buffer, 0, chunkSize, null);
      if (read <= 0) break;
      const data = buffer.subarray(0, read).toString('base64');
      const params = { path: target, data, mkdirs: !noMkdirs };
      if (append) {
        params.append = true;
      } else if (first) {
        params.truncate = true;
        params.offset = 0;
      } else {
        params.offset = offset;
      }
      const result = await rpcCall(ctx, 'write', params);
      offset = result.offset + result.written;
      sent += read;
      first = false;
      if (total && total > 2 * 1024 * 1024) {
        const now = Date.now();
        if (now - lastProgress > 250) {
          lastProgress = now;
          const percent = Math.floor((sent / total) * 100);
          process.stderr.write(`\rwrite ${formatSize(sent)} / ${formatSize(total)} (${percent}%)`);
        }
      }
    }
    const finalParams = { path: target, data: '', fsync: true, mkdirs: !noMkdirs };
    if (append) {
      finalParams.append = true;
    } else {
      finalParams.offset = offset;
      if (first) finalParams.truncate = true;
    }
    const final = await rpcCall(ctx, 'write', finalParams);
    if (ctx.json) {
      printJson({ path: target, written: sent, size: final.size, append });
    } else {
      process.stderr.write(`wrote ${formatSize(sent)} to ${safe(target)} (${final.size} bytes)\n`);
    }
  } finally {
    if (from) fs.closeSync(fd);
    if (total && total > 2 * 1024 * 1024) process.stderr.write('\n');
  }
}

async function commandMkdir(ctx, args) {
  requirePositional(args, 1, 'latchkey mkdir <path>');
  const result = await rpcCall(ctx, 'mkdir', { path: args[0] });
  if (ctx.json) printJson(result);
  else process.stdout.write((result.created ? 'created ' : 'exists  ') + safe(result.path) + '\n');
}

async function commandRm(ctx, args) {
  const recursive = takeFlag(args, ['-r', '--recursive']);
  const force = takeFlag(args, ['--force']);
  requirePositional(args, 1, 'latchkey rm <path> [--recursive] [--force]');
  const result = await rpcCall(ctx, 'delete', {
    path: args[0],
    recursive,
    force,
  });
  if (ctx.json) printJson(result);
  else process.stdout.write(`deleted ${result.deleted} path(s) at ${safe(result.path)}\n`);
}

async function commandMove(ctx, args) {
  const overwrite = takeFlag(args, ['--overwrite']);
  const force = takeFlag(args, ['--force']);
  requirePositional(args, 2, 'latchkey mv <from> <to> [--overwrite] [--force]');
  const result = await rpcCall(ctx, 'move', {
    from: args[0],
    to: args[1],
    overwrite,
    force,
  });
  if (ctx.json) printJson(result);
  else process.stdout.write(`${safe(result.from)} -> ${safe(result.to)}\n`);
}

async function commandCopy(ctx, args) {
  const overwrite = takeFlag(args, ['--overwrite']);
  requirePositional(args, 2, 'latchkey cp <from> <to> [--overwrite]');
  const result = await rpcCall(ctx, 'copy', {
    from: args[0],
    to: args[1],
    overwrite,
  });
  if (ctx.json) printJson(result);
  else process.stdout.write(`copied ${result.copied} file(s): ${safe(result.from)} -> ${safe(result.to)}\n`);
}

async function commandFind(ctx, args) {
  const name = takeOption(args, ['--name'], '');
  let glob = takeOption(args, ['--glob'], '');
  const maxDepth = Number(takeOption(args, ['--max-depth'], '16'));
  const limit = Number(takeOption(args, ['--limit'], '200'));
  const dirsOnly = takeFlag(args, ['--dirs-only']);
  const filesOnly = takeFlag(args, ['--files-only']);
  const hidden = takeFlag(args, ['--hidden']);
  const caseSensitive = takeFlag(args, ['--case-sensitive']);
  requirePositional(args, 1, 'latchkey find <path> [--name text] [--glob pattern]');
  if (!name && !glob) glob = '*';
  const result = await rpcCall(ctx, 'search', {
    path: args[0],
    name,
    glob,
    maxDepth,
    limit,
    dirs: !filesOnly,
    files: !dirsOnly,
    hidden,
    caseSensitive,
  });
  if (ctx.json) {
    printJson(result);
    return;
  }
  for (const match of result.matches) {
    process.stdout.write(safe(match.path) + (match.type === 'dir' ? '/' : '') + '\n');
  }
  if (result.truncated) {
    process.stderr.write(`... stopped at limit ${limit}\n`);
  }
}

async function commandLogs(ctx, args) {
  const clear = takeFlag(args, ['--clear']);
  if (clear) {
    if (args.length > 0) throw new Error('unexpected argument: ' + args[0]);
    const result = await rpcCall(ctx, 'logs-clear', {});
    if (ctx.json) {
      printJson(result);
      return;
    }
    process.stdout.write(`cleared ${result.files} file(s), ${result.bytes} bytes\n`);
    return;
  }
  const tail = Number(takeOption(args, ['--tail'], '500'));
  if (!Number.isInteger(tail) || tail < 1 || tail > 5000) {
    throw new Error('--tail must be an integer from 1 to 5000');
  }
  const since = Number(takeOption(args, ['--since'], '0'));
  if (!Number.isFinite(since) || since < 0) {
    throw new Error('--since must be a non-negative millisecond timestamp');
  }
  let minLevel = takeOption(args, ['--min-level', '--level'], '').toUpperCase();
  if (minLevel && !['DEBUG', 'INFO', 'WARN', 'ERROR'].includes(minLevel)) {
    throw new Error('--min-level must be DEBUG, INFO, WARN, or ERROR');
  }
  const cat = takeOption(args, ['--cat'], '');
  const output = takeOption(args, ['-o', '--output'], '');
  const result = await rpcCall(ctx, 'logs', { tail, since, minLevel, cat });
  
  if (output) {
    const text = result.entries.map((entry) => JSON.stringify(entry)).join('\n');
    fs.writeFileSync(output, text ? text + '\n' : '', { mode: 0o600 });
    fs.chmodSync(output, 0o600);
    process.stderr.write(`wrote ${result.entries.length} event(s) to ${safe(output)}\n`);
    return;
  }
  
  if (ctx.json) {
    printJson(result);
    return;
  }
  
  for (const entry of result.entries) {
    process.stdout.write(formatLogEntry(entry) + '\n');
  }
  if (result.truncated) {
    process.stderr.write('... truncated; increase --tail or use --since\n');
  }
}

async function commandWelcome(ctx) {
  const lines = [
    'Latchkey - secure file access portal for the Latchkey Android app.',
    '======================================================================',
    '',
    'Purpose:',
    '  This is an encrypted, authenticated bridge that provides the Latchkey Android',
    '  app with file access to the device storage - access that would otherwise be',
    '  blocked by host environment restrictions (e.g., free-tier sandboxing).',
    '',
    'Function:',
    '  - The Latchkey Android app runs a local HTTP server on 127.0.0.1:39401',
    '  - The client encrypts RPC requests with AES-256-GCM (AAD "LATCHKEY/1")',
    '  - The app decrypts, executes file operations, encrypts responses',
    '  - The client decrypts and prints results',
    '  - Activity log persists to JSONL and can be queried/exported',
    '',
    'Security model:',
    '  - Server binds to loopback only (127.0.0.1 / localhost)',
    '  - Every RPC requires a valid legacy key or a paired per-client key',
    '  - Paired keys are revocable and wrapped by Android Keystore',
    '  - Pairing links are single-use, expire in 2 minutes, and are rate-limited',
    '  - Replay protection (5 min window), timestamp validation (+/- 5 min)',
    '  - Immutable/protected roots enforced; sensitive paths denied',
    '  - Audit logging enabled',
    '',
    'How to use (human):',
    '  - Open the Latchkey app on the device, grant All Files access',
    '  - Start the foreground service (server listens on 127.0.0.1:39401)',
    '  - Tap Pair assistant to copy a 2-minute, single-use link',
    '  - Run:  latchkey pair --clipboard',
    '  - Later commands need no key; credentials are stored at 0600',
    '  - The legacy key remains available for older clients',
    '',
    'How to use (AI):',
    '  - Provide the key to the AI assistant running the bridge context',
    '  - Pair once with `latchkey pair --clipboard`, then use credentials',
    '  - Use the documented commands (health, ping, info, ls, stat, read, write,',
    '    get, put, mkdir, rm, mv, cp, find, logs, welcome)',
    '  - Prefer `logs` with `--tail` / `--min-level` for auditing',
    '  - Prefer `-o <file>` for binary reads',
    '',
    'Commands:',
    '  health                            plaintext reachability check (no key needed)',
    '  ping                              authenticated round-trip',
    '  info                              app, device, storage, roots, counters',
    '  ls <path> [--limit N] [--offset N]',
    '  stat <path>',
    '  read <path> [-o file] [--offset N] [--length N] [--chunk-size N]',
    '  get <remote> <local>              alias for read -o',
    '  write <path> --from <file> [--append] [--chunk-size N] [--no-mkdirs]',
    '  put <local> <remote>              alias for write --from',
    '  mkdir <path>',
    '  rm <path> [--recursive] [--force]',
    '  mv <from> <to> [--overwrite] [--force]',
    '  cp <from> <to> [--overwrite]',
    '  find <path> [--name text] [--glob pattern] [--max-depth N] [--limit N]',
    '               [--dirs-only|--files-only] [--hidden] [--case-sensitive]',
    '  logs [--tail N] [--since ms] [--min-level LEVEL] [--cat name] [-o file]',
    '                                    read the persistent activity log',
    '  welcome                          show a welcome page with app information',
    '',
    'Global options:',
    '  --key <key>         32-byte app key (or set LATCHKEY_KEY)',
    '  --key-file <file>   read the key from a file',
    '  --url <url>         default ' + DEFAULT_URL,
    '  --json              print the raw decrypted JSON response',
    '',
    'Examples:',
    '  latchkey --key "$KEY" health',
    '  latchkey --key "$KEY" ls /sdcard/Download',
    '  latchkey --key "$KEY" find /sdcard -name invoice --max-depth 6',
    '  latchkey --key "$KEY" get /sdcard/DCIM/Camera/photo.jpg ./photo.jpg',
    '  latchkey --key "$KEY" put ./notes.txt /sdcard/Documents/notes.txt',
    '  latchkey --key "$KEY" logs --tail 200 --min-level WARN',
    '  latchkey --key "$KEY" welcome'
  ];
  process.stdout.write(lines.join('\n') + '\n');
}

function usage() {
  process.stdout.write(`Latchkey client — encrypted file access to the Latchkey Android app.

Usage:
  latchkey pair [--clipboard] [--wait <seconds>] [--link <uri>]
  latchkey <command> [args...]

Pairing:
  pair                              read the pairing link from the clipboard
  pair --clipboard                  same, explicitly
  pair --link <uri>                 use a link directly instead of the clipboard
  pair --clipboard --wait 120       wait for a fresh link, then pair immediately

  Pairing stores a revocable per-client key in ~/.config/latchkey/credentials.json
  (mode 0600). Later commands use it automatically.

Commands:
  health                            plaintext reachability check (no key needed)
  ping                              authenticated round-trip
  info                              app, device, storage, roots, counters
  ls <path> [--limit N] [--offset N]
  stat <path>
  read <path> [-o file] [--offset N] [--length N] [--chunk-size N]
  get <remote> <local>              alias for read -o
  write <path> --from <file> [--append] [--chunk-size N] [--no-mkdirs]
  put <local> <remote>              alias for write --from
  mkdir <path>
  rm <path> [--recursive] [--force]
  mv <from> <to> [--overwrite] [--force]
  cp <from> <to> [--overwrite]
  find <path> [--name text] [--glob pattern] [--max-depth N] [--limit N]
               [--dirs-only|--files-only] [--hidden] [--case-sensitive]
  logs [--clear] [--tail N] [--since ms] [--min-level LEVEL] [--cat name] [-o file]
                                    read or clear the persistent activity log
  logs --pager                    read logs with a pager (less/more)
  welcome                          show a welcome page with app information

Global options:
  --key <key>         32-byte legacy app key (or set LATCHKEY_KEY)
  --key-file <file>   read the key from a file
  --url <url>         default ${DEFAULT_URL}
  --credentials <file> pairing credentials path
  --json              print the raw decrypted JSON response

Examples:
  latchkey pair --clipboard
  latchkey ping
  latchkey ls /sdcard/Download
  latchkey find /sdcard -name invoice --max-depth 6
  latchkey get /sdcard/DCIM/Camera/photo.jpg ./photo.jpg
  latchkey put ./notes.txt /sdcard/Documents/notes.txt
  latchkey logs --tail 200 --min-level WARN
  latchkey logs --clear
  latchkey --key "$KEY" health
`);
}

function readKeyFile(file) {
  if (!file) throw new Error('--key-file needs a path');
  const info = fs.statSync(file);
  if (!info.isFile()) throw new Error('key file is not a regular file');
  const mode = info.mode & 0o777;
  if ((mode & 0o077) !== 0) {
    process.stderr.write(`warning: ${safe(file)} is readable by other users; chmod 600 it\n`);
  }
  return fs.readFileSync(file, 'utf8');
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv.includes('-h') || argv.includes('--help')) {
    usage();
    return;
  }
  if (argv.includes('--version')) {
    process.stdout.write('latchkey client ' + CLIENT_VERSION + '\n');
    return;
  }

  let keyText = process.env.LATCHKEY_KEY || '';
  let keyExplicit = Boolean(process.env.LATCHKEY_KEY);
  let urlText = process.env.LATCHKEY_URL || DEFAULT_URL;
  let urlExplicit = Boolean(process.env.LATCHKEY_URL);
  let credentialsFile = credentialsPath();
  let json = false;
  let clipboard = false;
  let pairWait = 0;
  let pairLink = '';
  const rest = [];

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--key') {
      keyText = argv[++i] || '';
      keyExplicit = true;
    } else if (arg.startsWith('--key=')) {
      keyText = arg.slice('--key='.length);
      keyExplicit = true;
    } else if (arg === '--key-file') {
      keyText = readKeyFile(argv[++i]);
      keyExplicit = true;
    } else if (arg.startsWith('--key-file=')) {
      keyText = readKeyFile(arg.slice('--key-file='.length));
      keyExplicit = true;
    } else if (arg === '--url') {
      urlText = argv[++i] || '';
      urlExplicit = true;
    } else if (arg.startsWith('--url=')) {
      urlText = arg.slice('--url='.length);
      urlExplicit = true;
    } else if (arg === '--credentials') {
      const value = argv[++i];
      if (!value) throw new Error('--credentials needs a path');
      credentialsFile = path.resolve(value);
    } else if (arg.startsWith('--credentials=')) {
      credentialsFile = path.resolve(arg.slice('--credentials='.length));
    } else if (arg === '--json') {
      json = true;
    } else if (arg === '--clipboard') {
      clipboard = true;
    } else if (arg === '--wait') {
      pairWait = Number(argv[++i]);
    } else if (arg.startsWith('--wait=')) {
      pairWait = Number(arg.slice('--wait='.length));
    } else if (arg === '--link') {
      const value = argv[++i];
      if (!value) throw new Error('--link needs a pairing URI');
      pairLink = value;
    } else if (arg.startsWith('--link=')) {
      pairLink = arg.slice('--link='.length);
    } else {
      rest.push(arg);
    }
  }

  if (rest.length === 0) {
    usage();
    return;
  }
  const command = rest.shift();
  if (command !== 'pair' && (clipboard || pairLink || pairWait)) {
    throw new Error('--clipboard, --wait, and --link are only valid with the pair command');
  }

  if (command === 'pair') {
    if (rest.length > 0) {
      throw new Error('usage: latchkey pair [--clipboard] [--wait <seconds>] [--link <uri>]');
    }
    if (pairWait && (!Number.isInteger(pairWait) || pairWait < 1 || pairWait > 600)) {
      throw new Error('--wait must be a whole number of seconds between 1 and 600');
    }
    if (pairWait && pairLink) {
      throw new Error('--wait is only valid when reading the clipboard');
    }
    let link = pairLink;
    let usedClipboard = false;
    if (!link) {
      usedClipboard = true;
      link = pairWait ? await waitForPairLink(pairWait) : readClipboard();
    }
    if (!String(link).trim()) {
      throw new Error('the clipboard does not contain a pairing link');
    }
    const result = await pairWithLink(link, { credentialsFile });
    if (usedClipboard) {
      clearClipboard();
    }
    if (json) {
      printJson({ ...result.credentials, verified: result.verified });
    } else {
      process.stdout.write(`Paired with ${safe(result.credentials.name)}\n`);
      process.stdout.write(`  client      ${safe(result.credentials.clientId)}\n`);
      process.stdout.write(`  fingerprint ${safe(result.credentials.fingerprint)}\n`);
      process.stdout.write(`  credentials ${safe(result.credentials.path)} (0600)\n`);
      process.stdout.write(result.verified
        ? '  verified    ping succeeded\n'
        : '  verified    no (see warning)\n');
    }
    if (!result.verified) {
      process.stderr.write('warning: the key was saved, but the verification ping failed: '
        + safe(result.verificationError) + '\n');
    }
    return;
  }

  let credentials = null;
  let credentialsError = null;
  try {
    credentials = loadCredentials(credentialsFile);
  } catch (err) {
    credentialsError = err;
  }
  if (!urlExplicit && credentials) {
    urlText = credentials.url;
  }

  let clientId = '';
  if (command !== 'health' && !keyExplicit) {
    if (credentials) {
      keyText = credentials.key;
      clientId = credentials.clientId;
      if (!urlExplicit) urlText = credentials.url;
    } else if (credentialsError) {
      throw new Error('could not read pairing credentials: ' + credentialsError.message);
    }
  }

  const server = parseServerUrl(urlText);
  const ctx = {
    ...server,
    host: server.host,
    port: server.port,
    json,
    key: null,
    clientId: clientId || undefined,
    aad: clientId
      ? Buffer.from('LATCHKEY/1|client:' + clientId, 'utf8')
      : AAD,
  };
  if (command !== 'health') {
    ctx.key = decodeKey(keyText);
  }

  switch (command) {
    case 'health': await commandHealth(ctx, rest); break;
    case 'ping': await commandPing(ctx, rest); break;
    case 'info': await commandInfo(ctx, rest); break;
    case 'ls': case 'list': await commandLs(ctx, rest); break;
    case 'stat': await commandStat(ctx, rest); break;
    case 'read': case 'cat': await commandRead(ctx, rest, command); break;
    case 'get': {
      requirePositional(rest, 2, 'latchkey get <remote> <local>');
      await commandRead(ctx, [rest[0], '-o', rest[1]], 'get');
      break;
    }
    case 'write': await commandWrite(ctx, rest, command); break;
    case 'put': {
      requirePositional(rest, 2, 'latchkey put <local> <remote>');
      await commandWrite(ctx, [rest[1], '--from', rest[0]], 'put');
      break;
    }
    case 'mkdir': await commandMkdir(ctx, rest); break;
    case 'rm': case 'delete': await commandRm(ctx, rest); break;
    case 'mv': case 'move': await commandMove(ctx, rest); break;
    case 'cp': case 'copy': await commandCopy(ctx, rest); break;
    case 'find': case 'search': await commandFind(ctx, rest); break;
    case 'logs': await commandLogs(ctx, rest); break;
    case 'welcome': await commandWelcome(ctx); break;
    default:
      throw new Error('unknown command: ' + command + ' (try --help)');
  }
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (invokedPath && invokedPath === path.resolve(fileURLToPath(import.meta.url))) {
  main().catch((err) => {
    process.stderr.write('latchkey: '
      + safe(err && err.message ? err.message : String(err)) + '\n');
    process.exit(1);
  });
}
