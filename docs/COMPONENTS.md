# Component map

The platform now contains foundations for Secure Update, Fleet Manager, Immutable
Logs, Recovery Center, Compliance Engine, Honeypot Grid, Certificate Manager,
Container Guardian, Secure Mesh, Digital Evidence Vault, Phishing Defense, and
Privacy OS Profile. Each is opt-in and documented under `components/`.

Production hardening still requires an external identity provider, authenticated
TLS ingress, immutable remote logging, key rotation, and environment-specific
review. The foundations intentionally avoid silently changing networks, sending
messages, or applying updates.
