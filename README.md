# SafeStack Zero Trust

Local-first policy decision engine for devices, users, resources and actions.
It applies **default deny**, checks device posture, records every decision in
SQLite, and provides an Ed25519 signing foundation for policy bundles.

## Components

The platform includes the Zero Trust decision engine and the [SafeStack Identity](docs/IDENTITY.md) registry.

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/safestack-zt device-add --id laptop-1 --name laptop --owner alice --posture compliant
.venv/bin/safestack-zt policy-add --effect allow --subject alice --resource vpn --action connect --min-posture compliant
.venv/bin/safestack-zt authorize --device laptop-1 --subject alice --resource vpn --action connect
```

An authorization failure exits with code 2. This MVP does not change firewall
rules or grant OS privileges. See [THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Architecture

```mermaid
flowchart LR
    U[User or service] --> I[Identity registry]
    I --> P[Policy as Code]
    D[Device posture] --> E[Decision engine]
    P --> E
    E --> A[Allow or deny]
    E --> L[Audit and SOC events]
    S[Encrypted secrets] --> E
    C[Supply-chain SBOM] --> V[Verification]
```

## X/Y risk view

The X axis represents likelihood and the Y axis represents impact. Items in the
upper-right quadrant deserve the earliest review.

```mermaid
quadrantChart
    title Zero Trust review priority
    x-axis Low likelihood --> High likelihood
    y-axis Low impact --> High impact
    quadrant-1 Immediate review
    quadrant-2 Impact review
    quadrant-3 Monitor
    quadrant-4 Likelihood review
    Compromised identity: [0.82, 0.88]
    Unregistered device: [0.72, 0.70]
    Missing policy: [0.55, 0.58]
    Stale SBOM: [0.42, 0.46]
    Failed login burst: [0.68, 0.76]
```


## License

Released under the [MIT License](LICENSE).
