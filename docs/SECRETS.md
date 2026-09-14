# Secrets and supply chain

`zt.secrets` stores a JSON payload encrypted with Fernet and restricts key/store
files to owner permissions. Keep the key outside the repository and rotate it
through an approved operational process. The module does not print secret
values. Production deployments should prefer an HSM or OS keychain.

`zt.supply_chain` creates a CycloneDX-compatible file inventory with SHA-256
digests. Review the generated SBOM and pair it with dependency scanners and
signed release metadata before distribution.
