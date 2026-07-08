# doorbell-enclave-server

The secret-recipient side of the **doorbell pattern**: boots with no secrets
and rings the KMS client's doorbell (`POST /ring` with its own hostname)
every 15 seconds until the secret arrives. The ring carries no credentials
and no secrets; the KMS client attests this enclave and pushes the secret to
`/secrets` over the attested TLS channel.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Liveness |
| `/secrets` | POST | Receives the secret from the KMS client |
| `/status` | GET | `{"received": bool, "fingerprint": "sha256:..."}` |

Environment: `KMS_URL` (where to ring), `DOMAIN` (this enclave's own public
hostname, injected by the platform).

See the parent blueprint repo for the full pattern explanation, sequence
diagram, and demo walkthrough.
