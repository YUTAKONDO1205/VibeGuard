# VibeGuard sample: Ruby weak crypto patterns.

require 'digest'

# VG-CRYPTO-001 — MD5 fingerprint over user data.
def legacy_fingerprint(payload)
  Digest::MD5.hexdigest(payload)
end

# VG-CRYPTO-001 — SHA1 used as a "secure" hash.
def legacy_signature(data)
  Digest::SHA1.hexdigest(data)
end

# VG-CRYPTO-002 — Kernel#rand for a session id.
def new_session_id
  session_id = rand(1_000_000)
  session_id
end

# VG-CRYPTO-002 — Random.new for a token.
def new_token
  token = Random.new.bytes(32)
  token
end
