# Client KMS: Attested Secret Delivery to Enclaves

A minimal example of a **KMS client** delivering secrets into an enclave.
The enclave boots with no secrets and announces itself ("rings a doorbell");
the KMS client verifies it via remote attestation, then pushes the secrets
over the attested TLS channel.

## How It Works

```
  KMS Client                            Enclave Server
  (trusted operator-side process,       (confidential enclave,
   runs anywhere: laptop, EC2, ...)      boots with no secrets)
        │                                     │
        │ 0. loads secrets from its           │
        │    backend (.env file here)         │
        │                                     │
        │  1. RING: POST /ring                │
        │     {"host": "enclave.example.dev"} │
        │<────────────────────────────────────│
        │     plain HTTP, no credentials,     │
        │     no secrets, no authority        │
        │                                     │
        │  2. ATTEST: remote attestation      │
        │────────────────────────────────────>│
        │     verifies the host runs the      │
        │     exact code released from        │
        │     ENCLAVE_REPO                    │
        │                                     │
        │  3. DELIVER: POST /secrets          │
        │────────────────────────────────────>│
        │     over the attested TLS channel   │
```

Why this is secure:

- **The ring carries no authority.** Anyone can ring, with any hostname.
  The hostname is a delivery hint, not a claim of identity.
- **Trust comes from attestation, not credentials.** The KMS client only
  delivers to a host that proves it runs the exact code released from the
  GitHub repo pinned in `ENCLAVE_REPO`.
- **Secrets never appear in the `/ring` response.** They only travel over
  the attested channel, so a malicious ring can at worst trigger a delivery
  to a legitimate enclave.
- **Secrets live in enclave memory only.** On restart, the enclave rings
  again.

The KMS client itself needs no attestation: it already holds the secrets.
The pattern protects delivery *into* the enclave.

## Components

### `kms-client/` — holds and delivers secrets (not an enclave)

A pure Go program. Reads secrets from a `.env`-style file; swap the
`loadSecrets` function in `main.go` for AWS Secrets Manager, Vault, etc.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ring` | POST | `{"host": "<enclave hostname>"}` — attest, then deliver |
| `/health` | GET | Liveness |

Env: `ENCLAVE_REPO` (required — the trust decision), `SECRETS_FILE`
(default `secrets.env`), `PORT` (default `8080`).

### `enclave-server/` — receives secrets (the enclave)

Rings the KMS client on start, retries every 5 minutes until delivery.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/secrets` | POST | Receives secrets from the KMS client |
| `/status` | GET | `{"received": bool, "keys": [...]}` — names only |
| `/health` | GET | Liveness |

Env: `KMS_URL` (where to ring), `DOMAIN` (own public hostname, injected by
the platform).

## The Core Code

The entire pattern is one handler in `kms-client/main.go`:

```go
// Remote attestation: verify req.Host runs the exact code released from
// ENCLAVE_REPO; get an HTTP client pinned to the attested enclave.
httpClient, err := tinfoil.NewEnclaveHTTPClient(r.Context(), req.Host, tinfoil.Pin{Repo: s.enclaveRepo}, nil)
if err != nil { /* 502 — nothing delivered */ }

// Deliver over the attested channel, never in the /ring response.
httpClient.Post("https://"+req.Host+"/secrets", ...)
```

`NewEnclaveHTTPClient` is from [`tinfoil-go`](https://github.com/tinfoilsh/tinfoil-go).

## Running

Deploy the enclave server (below), then run the KMS client anywhere:

```sh
cd kms-client
cp secrets.env.example secrets.env   # edit values
ENCLAVE_REPO=your-org/doorbell-enclave-server go run .
```

If `KMS_URL` is reachable from the enclave, secrets arrive automatically on
boot. If not (e.g. laptop behind NAT), ring on the enclave's behalf:

```sh
curl -X POST localhost:8080/ring \
  -H 'Content-Type: application/json' \
  -d '{"host": "<enclave-hostname>"}'
```

Verify:

```sh
curl https://<enclave-hostname>/status
# {"received": true, "keys": ["API_KEY", "DATABASE_PASSWORD", "SIGNING_KEY"]}
```

## Deploying the Enclave Server

Attestation binds the enclave's identity to the GitHub repo that released
its code, so `enclave-server/` must be its own repo:

1. Push `enclave-server/` as its own repo, replacing `example-org` in
   `go.mod` and `tinfoil-config.yml`.
2. Run the `Tinfoil Release` workflow (builds, measures, and publishes the
   signed release that attestation verifies against).
3. Deploy on Tinfoil; point the KMS client's `ENCLAVE_REPO` at the repo.

The KMS client is just a static Go binary — no container or release process
needed.
