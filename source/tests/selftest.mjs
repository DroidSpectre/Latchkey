#!/usr/bin/env node
// Protocol self-test: Node <-> Node round trip plus Node <-> Java AES-GCM interop.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import {
  decodeKey,
  decryptPayload,
  encryptPayload,
  normalizeClipboardText,
  pairWithLink,
  parsePairLink,
  parseServerUrl,
  rpcCall,
} from '../client/latchkey.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const run = promisify(execFile);
const cli = path.join(here, '..', 'client', 'latchkey.mjs');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'latchkey-test-'));
const keyBytes = crypto.randomBytes(32);
const keyText = keyBytes.toString('base64url');
const key = decodeKey(keyText);

assert.equal(key.length, 32);
assert.throws(() => decodeKey('nope'), /43 base64url/);
assert.throws(() => decodeKey('A'.repeat(43) + '='), /43 base64url/);
assert.throws(() => decodeKey('!'.repeat(43)), /43 base64url/);
assert.throws(() => parseServerUrl('http://192.168.1.10:39401'), /127\.0\.0\.1|loopback/);
assert.throws(() => parseServerUrl('https://127.0.0.1:39401'), /http/);
assert.throws(() => parseServerUrl('http://127.0.0.1:39401/other'), /path|credential/);
assert.equal(parseServerUrl('http://localhost:39401').host, '127.0.0.1');

const pairTokenBytes = crypto.randomBytes(32);
const pairToken = pairTokenBytes.toString('base64url');
const pairExpires = Date.now() + 120000;
const validPairLink = 'latchkey://pair?scope=loopback&v=1&id='
  + '0123456789abcdef0123456789abcdef'
  + '&name=Test%20Device&host=127.0.0.1&port=39401&fp=ABCDEF0123456789'
  + '&tok=' + pairToken + '&exp=' + pairExpires;
const parsedLink = parsePairLink(validPairLink);
assert.equal(parsedLink.port, 39401);
assert.equal(parsedLink.token, pairToken);
assert.equal(parsedLink.name, 'Test Device');
assert.throws(() => parsePairLink(validPairLink.replace('scope=loopback', 'scope=lan')),
  /loopback/);
assert.throws(() => parsePairLink(validPairLink.replace('host=127.0.0.1', 'host=192.168.1.2')),
  /loopback/);
assert.throws(() => parsePairLink(validPairLink.replace(/exp=\d+/, 'exp=' + (Date.now() - 1000))),
  /expired/);
assert.throws(() => parsePairLink(validPairLink.replace('latchkey://pair', 'http://pair')),
  /pairing link/);
assert.equal(normalizeClipboardText(JSON.stringify({
  result: validPairLink,
  output: '',
})), validPairLink);
assert.equal(normalizeClipboardText(validPairLink), validPairLink);
console.log('pair link parsing ok');

const plaintext = crypto.randomBytes(4096);
const payload = { bin: plaintext.toString('base64'), note: 'round trip' };
const blob = encryptPayload(key, payload);
const decrypted = JSON.parse(decryptPayload(key, blob).toString('utf8'));
assert.deepEqual(decrypted, payload);

const tampered = Buffer.from(blob);
tampered[tampered.length - 1] ^= 0xff;
assert.throws(() => decryptPayload(key, tampered));

console.log('node crypto round-trip ok');

const classes = path.join(tmp, 'classes');
fs.mkdirSync(classes);
execFileSync('javac', ['-d', classes, path.join(here, 'CryptoInterop.java')], {
  stdio: 'inherit',
});
console.log('java interop compiled');

const plainFile = path.join(tmp, 'plain.bin');
const nodeBlob = path.join(tmp, 'node.blob');
const javaPlain = path.join(tmp, 'java-plain.bin');
const javaBlob = path.join(tmp, 'java.blob');
const nodePlain = path.join(tmp, 'node-plain.bin');
fs.writeFileSync(plainFile, plaintext);
fs.writeFileSync(nodeBlob, encryptPayload(key, { hello: 'world', n: 42 }));

execFileSync('java', ['-cp', classes, 'CryptoInterop', 'decrypt', keyText,
  nodeBlob, javaPlain], { stdio: 'inherit' });
assert.equal(fs.readFileSync(javaPlain, 'utf8'), JSON.stringify({ hello: 'world', n: 42 }));
console.log('java decrypted a node payload');

execFileSync('java', ['-cp', classes, 'CryptoInterop', 'encrypt', keyText,
  plainFile, javaBlob], { stdio: 'inherit' });
fs.writeFileSync(nodePlain, decryptPayload(key, fs.readFileSync(javaBlob)));
assert.deepEqual(fs.readFileSync(nodePlain), plaintext);
console.log('node decrypted a java payload');

const remoteContent = Buffer.from('hello from the fake device\n');
const written = new Map();
let pairedClientId = '';
const pairedKey = crypto.randomBytes(32);
let issuedPair = false;
let lastClientId = null;

function rawSeal(rawKey, aad, plaintext) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', rawKey, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]);
}

function keyFor(clientId) {
  if (clientId === pairedClientId) return pairedKey;
  return key;
}

function aadFor(clientId) {
  return clientId ? Buffer.from('LATCHKEY/1|client:' + clientId, 'utf8') : undefined;
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      app: 'latchkey', ok: true, version: '1.1.0', port: 39401,
      uptimeMs: 12345, requests: 0,
    }));
    return;
  }
  if (req.method === 'POST' && req.url === '/pair') {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      let request;
      try {
        request = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, code: 'BAD_REQUEST', error: 'invalid json' }));
        return;
      }
      if (request.v !== 1 || request.token !== pairToken
          || !request.client || !/^[a-f0-9]{32}$/.test(request.client.id)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, code: 'BAD_TOKEN', error: 'invalid token' }));
        return;
      }
      issuedPair = true;
      pairedClientId = request.client.id;
      const pairKey = crypto.createHash('sha256').update(pairToken, 'utf8').digest();
      const aad = Buffer.from('LATCHKEY/PAIR/1|' + request.client.id, 'utf8');
      const blob = rawSeal(pairKey, aad, pairedKey);
      pairKey.fill(0);
      const fingerprint = crypto.createHash('sha256').update(pairedKey).digest()
        .subarray(0, 8).toString('hex').toUpperCase();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ok: true,
        v: 1,
        clientId: request.client.id,
        clientName: request.client.name,
        key: blob.toString('base64url'),
        fingerprint,
        serverTime: Date.now(),
      }));
    });
    return;
  }
  if (req.method !== 'POST' || req.url !== '/rpc') {
    res.writeHead(404);
    res.end();
    return;
  }
  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  req.on('end', () => {
    const clientId = req.headers['x-latchkey-client'] || null;
    lastClientId = clientId;
    const useKey = keyFor(clientId);
    const useAad = aadFor(clientId);
    if (clientId && clientId !== pairedClientId) {
      res.writeHead(401);
      res.end();
      return;
    }
    const request = JSON.parse(decryptPayload(useKey, Buffer.concat(chunks), useAad).toString('utf8'));
    let response;
    if (request.path === '/bad-id') {
      response = { ok: true, id: 'wrong-id', serverTime: Date.now() };
    } else if (request.path === '/stale-time') {
      response = {
        ok: true,
        id: request.id,
        serverTime: Date.now() - 10 * 60 * 1000,
      };
    } else if (request.op === 'ping') {
      response = {
        ok: true,
        app: 'latchkey',
        version: '1.1.0',
        id: request.id,
        port: 39401,
        uptimeMs: 12345,
        keyFingerprint: 'DEADBEEFDEADBEEF',
      };
    } else if (request.op === 'logs') {
      response = {
        ok: true,
        id: request.id,
        entries: [{
          t: Date.now(), level: 'INFO', cat: 'test', event: 'test', msg: 'hello',
        }],
        count: 1,
        matched: 1,
        tail: 1,
        since: 0,
        nextSince: Date.now(),
        truncated: false,
        files: [],
      };
    } else if (request.op === 'list') {
      response = {
        ok: true,
        id: request.id,
        path: request.path,
        total: 1,
        truncated: false,
        entries: [{ name: 'demo.txt', type: 'file', size: 5, mtime: 0 }],
      };
    } else if (request.op === 'read') {
      if (request.path !== '/remote.txt') {
        response = { ok: false, id: request.id, code: 'NOT_FOUND', error: 'missing' };
      } else {
        const offset = Number(request.offset) || 0;
        const length = Number(request.length) || 1024 * 1024;
        const slice = remoteContent.subarray(offset, offset + length);
        const next = offset + slice.length;
        response = {
          ok: true,
          id: request.id,
          path: request.path,
          offset,
          nextOffset: next,
          eof: next >= remoteContent.length,
          size: remoteContent.length,
          mtime: 0,
          data: slice.toString('base64'),
        };
      }
    } else if (request.op === 'write') {
      let buffer = written.get(request.path) || Buffer.alloc(0);
      if (request.truncate) buffer = Buffer.alloc(0);
      const at = request.append ? buffer.length : (Number(request.offset) || 0);
      const data = Buffer.from(request.data || '', 'base64');
      const end = at + data.length;
      if (buffer.length < end) {
        const grown = Buffer.alloc(end);
        buffer.copy(grown);
        buffer = grown;
      }
      data.copy(buffer, at);
      written.set(request.path, buffer);
      response = {
        ok: true,
        id: request.id,
        path: request.path,
        offset: at,
        written: data.length,
        size: buffer.length,
        mtime: 0,
      };
    } else {
      response = { ok: false, id: request.id, code: 'BAD_OP', error: 'unknown op' };
    }
    if (typeof response.serverTime !== 'number') {
      response.serverTime = Date.now();
    }
    const out = encryptPayload(useKey, response, useAad);
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Length': out.length,
    });
    res.end(out);
  });
});

await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;
try {
  const ping = await rpcCall({ key, host: '127.0.0.1', port }, 'ping');
  assert.equal(ping.ok, true);
  assert.equal(ping.version, '1.1.0');
  const list = await rpcCall({ key, host: '127.0.0.1', port }, 'list', {
    path: '/sdcard/Download',
  });
  assert.equal(list.entries[0].name, 'demo.txt');
  await assert.rejects(
    rpcCall({ key, host: '127.0.0.1', port }, 'nope'),
    (err) => err.code === 'BAD_OP',
  );
  await assert.rejects(
    rpcCall({ key, host: '127.0.0.1', port }, 'ping', { path: '/bad-id' }),
    /id does not match/,
  );
  await assert.rejects(
    rpcCall({ key, host: '127.0.0.1', port }, 'ping', { path: '/stale-time' }),
    /timestamp/,
  );
  const logResult = await rpcCall({ key, host: '127.0.0.1', port }, 'logs', { tail: 1 });
  assert.equal(logResult.entries[0].event, 'test');
  console.log('rpc client/server round-trip ok');

  const url = `http://127.0.0.1:${port}`;
  const health = await run(process.execPath, [cli, '--url', url, 'health']);
  assert.match(health.stdout, /latchkey 1\.1\.0/);
  const logsCli = await run(process.execPath, [cli, '--key', keyText, '--url', url,
    'logs', '--tail', '1']);
  assert.match(logsCli.stdout, /test/);

  const outOk = path.join(tmp, 'out.txt');
  fs.writeFileSync(outOk, 'ORIGINAL');
  await run(process.execPath, [cli, '--key', keyText, '--url', url,
    'get', '/remote.txt', outOk]);
  assert.equal(fs.readFileSync(outOk, 'utf8'), remoteContent.toString('utf8'));
  assert.equal(fs.readdirSync(tmp).filter((name) => name.includes('.latchkey-part-')).length, 0);

  const outKeep = path.join(tmp, 'keep.txt');
  fs.writeFileSync(outKeep, 'KEEP');
  await assert.rejects(
    run(process.execPath, [cli, '--key', keyText, '--url', url,
      'get', '/missing', outKeep]),
    (err) => err.code === 1,
  );
  assert.equal(fs.readFileSync(outKeep, 'utf8'), 'KEEP');
  assert.equal(fs.readdirSync(tmp).filter((name) => name.includes('.latchkey-part-')).length, 0);

  const localPut = path.join(tmp, 'note.txt');
  fs.writeFileSync(localPut, 'uploaded bytes');
  await run(process.execPath, [cli, '--key', keyText, '--url', url,
    'put', localPut, '/upload/note.txt']);
  assert.equal(written.get('/upload/note.txt').toString('utf8'), 'uploaded bytes');
  const credsFile = path.join(tmp, 'credentials.json');
  const link = 'latchkey://pair?scope=loopback&v=1&id='
    + '0123456789abcdef0123456789abcdef'
    + '&name=Test%20Device&host=127.0.0.1&port=' + port
    + '&fp=ABCDEF0123456789&tok=' + pairToken
    + '&exp=' + (Date.now() + 120000);
  const paired = await pairWithLink(link, { credentialsFile: credsFile });
  assert.equal(paired.verified, true);
  assert.equal(paired.credentials.clientId, pairedClientId);
  assert.match(paired.credentials.clientId, /^[a-f0-9]{32}$/);
  assert.equal(issuedPair, true);
  assert.equal(fs.statSync(credsFile).mode & 0o777, 0o600);
  const credsText = fs.readFileSync(credsFile, 'utf8');
  assert.equal(credsText.includes(pairToken), false);
  assert.equal(credsText.includes('latchkey://'), false);
  const autoPing = await run(process.execPath, [cli, '--credentials', credsFile, 'ping']);
  assert.match(autoPing.stdout, /pong/);
  assert.equal(lastClientId, pairedClientId);
  const direct = await rpcCall({
    key: pairedKey,
    host: '127.0.0.1',
    port,
    clientId: pairedClientId,
    aad: Buffer.from('LATCHKEY/1|client:' + pairedClientId, 'utf8'),
  }, 'ping');
  assert.equal(direct.ok, true);
  console.log('pairing + credentials + client AAD ok');
  console.log('client CLI get/put/health ok');
} finally {
  server.close();
}

fs.rmSync(tmp, { recursive: true, force: true });
console.log('selftest ok');
