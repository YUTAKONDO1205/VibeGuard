<?php
// VibeGuard safe sample: PHP using the right primitives.
// This file MUST produce zero findings.

// SHA-256 for integrity (not flagged — only MD5/SHA1 are flagged).
function integritySum(string $data): string {
    return hash('sha256', $data);
}

// password_hash uses bcrypt/argon2 by default — correct for credentials.
function hashPassword(string $password): string {
    return password_hash($password, PASSWORD_DEFAULT);
}

// random_bytes is a CSPRNG — correct for tokens.
function newSessionToken(): string {
    return bin2hex(random_bytes(32));
}

// random_int is a CSPRNG — correct for numeric secrets.
function newOtpNonce(): int {
    return random_int(100000, 999999);
}
