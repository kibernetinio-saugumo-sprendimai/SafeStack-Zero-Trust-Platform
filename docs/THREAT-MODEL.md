# Threat model

The trust boundary is the local policy database and its operator. The engine
protects against accidental over-permission through default deny, posture gates,
explicit deny precedence, and an append-style decision record. It does not yet
attest hardware, replace an identity provider, or defend against a compromised
host root account. Production deployment requires encrypted storage, key
rotation, operator MFA, backup testing, and an external immutable log sink.
