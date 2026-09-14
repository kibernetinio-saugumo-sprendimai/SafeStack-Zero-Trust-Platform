# SafeStack platform components

These components are deliberately separated so each can be deployed, reviewed,
and disabled independently. The shared implementation helpers live in `zt/extensions.py`.

| Component | Current foundation |
|---|---|
| secure-update | Hash-based update manifest; apply/signing workflow remains operator controlled |
| fleet-manager | Device inventory backed by the Zero Trust SQLite store |
| immutable-logs | Hash-chained local event records |
| recovery-center | Evidence and digest primitives for restore verification |
| compliance-engine | Control/evidence evaluation |
| honeypot-grid | Safe alert event model; no exposed listener by default |
| certificate-manager | Read-only TLS certificate retrieval |
| container-guardian | Deterministic image identifier primitive; pair with registry scanners |
| secure-mesh | Validated peer descriptor for WireGuard orchestration |
| digital-evidence-vault | Content sealing primitive |
| phishing-defense | Training-only simulation object; never sends mail |
| privacy-os-profile | Declarative settings comparison |
