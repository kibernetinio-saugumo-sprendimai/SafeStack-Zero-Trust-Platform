# SafeStack SOC Core

The SOC collector accepts structured JSON events and applies deterministic,
reviewable rules. The first rules detect repeated failed authentication and
authorization attempts caused by an unregistered device or missing policy.
Alerts are advisory; the collector does not block accounts or change network
controls automatically. Production use should add an immutable remote sink,
clock synchronization, retention policy, and analyst review workflow.
