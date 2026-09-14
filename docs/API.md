# Local API and dashboard

Run the dashboard from the project root:

```bash
safestack-zt serve --db zero-trust.db --port 8787
```

It binds to `127.0.0.1` by default. `GET /health` returns a health document,
`GET /api/snapshot` returns devices, policies, and recent decisions, and `/`
serves the SafeStack dashboard. Put it behind an authenticated reverse proxy
before any non-local exposure; the built-in server intentionally has no remote
authentication.

Remote binding is rejected unless `--allow-remote` is explicitly supplied; use
an authenticated TLS reverse proxy before enabling that option.
