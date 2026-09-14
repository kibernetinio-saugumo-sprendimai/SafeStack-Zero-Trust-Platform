# Policy as Code

Policies can be reviewed and versioned as JSON before they enter the decision
engine. Every entry requires `id`, `effect`, `subject`, `resource`, `action`, and
`min_posture`; unknown fields are tolerated for forward compatibility, while
missing or invalid required values fail validation.

```json
{"policies":[{"id":"vpn-admin","effect":"allow","subject":"alice","resource":"vpn","action":"connect","min_posture":"compliant"}]}
```
