# SafeStack Identity

The identity registry is local-first and designed to feed the Zero Trust policy
engine. Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes with 600,000
iterations; plaintext passwords are never stored or logged. Users can be active
or disabled, roles are explicit, and authentication events are recorded.

This is an identity component, not a replacement for a production IdP. Before
internet exposure, add MFA/WebAuthn, rate limiting, encrypted database storage,
key rotation, and an external immutable audit sink.
