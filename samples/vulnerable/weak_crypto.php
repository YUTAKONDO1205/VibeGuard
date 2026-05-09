<?php
// VibeGuard sample: PHP weak crypto patterns. None of these are safe.

// VG-CRYPTO-001 — MD5 of a password.
function legacyHash(string $password): string {
    return md5($password);
}

// VG-CRYPTO-001 — SHA1 of arbitrary data treated as integrity.
function legacyChecksum(string $data): string {
    return sha1($data);
}

// VG-CRYPTO-002 — non-CSPRNG used to mint a session token.
function newSessionToken(): string {
    $token = mt_rand(0, PHP_INT_MAX);
    return (string) $token;
}

// VG-CRYPTO-002 — bare rand() used for an OTP nonce.
function otpNonce(): int {
    $nonce = rand(100000, 999999);
    return $nonce;
}
