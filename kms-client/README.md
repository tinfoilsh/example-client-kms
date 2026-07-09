# doorbell-kms-client

The secret-holding side of the **doorbell pattern**. Not an enclave: a plain
Go service the operator runs wherever secrets are available (laptop, EC2,
next to your secret manager).

It loads secrets from a `.env`-style file at startup (`loadSecrets` in
`main.go` is the single integration point to swap in AWS Secrets Manager,
Vault, etc.) and delivers them to enclaves that ring `/ring` — but only
after verifying, via remote attestation, that the destination runs the exact
code released from the GitHub repo pinned in `ENCLAVE_REPO`.

Secrets are never returned in the `/ring` response; they are pushed out over
the attested TLS channel to the enclave's `/secrets` endpoint.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Liveness |
| `/ring` | POST | `{"host": "<enclave hostname>"}` — attest, then deliver |

Run:

```sh
cp secrets.env.example secrets.env   # edit with your values
ENCLAVE_REPO=your-org/doorbell-enclave-server go run .
```

Environment: `ENCLAVE_REPO` (required, the trust decision),
`SECRETS_FILE` (default `secrets.env`), `PORT` (default `8080`).

To deploy (EC2, a VM, systemd, anywhere), cross-compile a single static
binary — no container or release process needed:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o kms-client .
```

See the parent blueprint repo for the full pattern explanation.
