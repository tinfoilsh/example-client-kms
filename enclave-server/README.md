# doorbell-enclave-server

The secret-receiving side of the **doorbell pattern**: a confidential
enclave workload that boots with no secrets and rings the KMS client's
doorbell (`POST /ring` with its own hostname) — once on start, then retrying
every 5 minutes until secrets arrive. The ring carries no credentials and no
secrets; the KMS client attests this enclave and pushes the secrets to
`/secrets` over the attested TLS channel.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Liveness |
| `/secrets` | POST | Receives the secrets from the KMS client |
| `/status` | GET | `{"received": bool, "keys": [...]}` — names only, never values |

Environment: `KMS_URL` (where to ring; optional if the operator rings on
this enclave's behalf), `DOMAIN` (this enclave's own public hostname,
injected by the platform).

See the parent blueprint repo for the full pattern explanation, sequence
diagram, and deployment steps.
