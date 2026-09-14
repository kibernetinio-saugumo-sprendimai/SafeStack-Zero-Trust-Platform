# SafeStack platform audit

Date: 2026-09-14

## Scope

The audit covered the local repositories `Safestack-Sentinel`,
`Safestack-suite`, `Safestack-Zero-Trust`, and the canonical
`SafeStack-Zero-Trust-Platform`. It included source review, CLI smoke checks,
Python compilation, unit tests, key permission checks, and the localhost API.
No third-party targets were scanned.

## Verification

- Sentinel: 4/4 tests passed.
- Suite: 2/2 tests passed.
- Zero Trust Platform: 12/12 tests passed with the project virtual environment.
- Zero Trust legacy repository: 2/2 tests passed.
- Python compilation passed for all reviewed source trees.
- Dashboard `/health` returned `status: ok` on loopback.
- Private key files are created with owner-only `0600` permissions.
- Git working trees were clean after the fixes.

## Findings and status

| ID | Severity | Finding | Status |
|---|---|---|---|
| ZT-001 | High | Dashboard could previously be bound remotely without an explicit safety gate. | Fixed: remote binding now requires `--allow-remote`. |
| KEY-001 | High | Generated Ed25519 private keys previously inherited process umask. | Fixed: key files now use `0600` in Sentinel and Zero Trust repositories. |
| AUTH-001 | Medium | Identity registry has no MFA, login throttling, or account lockout. | Open; required before internet exposure. |
| LOG-001 | Medium | Local SQLite/JSONL logs can be modified by a privileged local user. | Open; add an immutable remote sink and signed checkpoints. |
| API-001 | Medium | Remote mode has no built-in authentication or TLS. | Mitigated by loopback default; use an authenticated TLS reverse proxy before enabling remote mode. |
| CI-001 | Low | GitHub Actions use version tags instead of pinned commit SHAs. | Open; pin actions for higher supply-chain assurance. |
| DEP-001 | Low | A live dependency vulnerability database was unavailable in this offline audit environment. | Open; run `pip-audit` and Bandit in CI and review results. |
| PRIV-001 | Low | Incident collection and inventory reports can contain sensitive host data. | Documented; protect output directories and define retention. |

## Recommendation order

Implement MFA and rate limiting, signed/remote immutable audit logs, and pinned
CI actions before exposing the dashboard outside localhost. Keep the legacy
`Safestack-Zero-Trust` repository as a compatibility snapshot; use
`SafeStack-Zero-Trust-Platform` as the canonical implementation.

This report is a source and local-runtime review, not a certification or a
penetration test. Re-run dependency and container scans in a network-enabled CI
environment before production deployment.
