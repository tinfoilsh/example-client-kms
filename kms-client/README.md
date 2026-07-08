# doorbell-kms-client

The secret-holder side of the **doorbell pattern**: holds a secret in memory
and delivers it to enclave servers that ring `/ring` — but only after
verifying, via remote attestation, that the destination runs the exact code
released from the GitHub repo pinned in `ENCLAVE_REPO`.

The secret is never returned in the `/ring` response; it is pushed out over
the attested TLS channel to the enclave's `/secrets` endpoint.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Liveness |
| `/ring` | POST | `{"host": "<enclave hostname>"}` — attest, then deliver |
| `/secret_info` | GET | SHA-256 fingerprint of the secret (never the secret) |

Environment: `ENCLAVE_REPO` (required) — the trust decision.

See the parent blueprint repo for the full pattern explanation, sequence
diagram, and demo walkthrough.
