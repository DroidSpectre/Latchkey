package io.latchkey.bridge;

final class RpcError extends Exception {
    final String code;

    RpcError(String code, String message) {
        super(message);
        this.code = code;
    }
}
