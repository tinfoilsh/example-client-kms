# The Doorbell Pattern: Attested Secret Delivery to Enclaves

A minimal blueprint for delivering secrets into enclaves using the
**doorbell pattern**: an enclave that needs secrets "rings a doorbell", and
a trusted KMS client — after verifying the enclave via remote attestation —
pushes the secrets into it over an attested TLS channel.

This repo contains exactly two services and nothing else. It exists to
exemplify the pattern in isolation.

## The Problem

An enclave workload boots with no secrets. It needs API keys, credentials,
key material — but:

- Baking secrets into the image would expose them to anyone with the image.
- Letting the enclave *pull* secrets would require the secret holder to
  authenticate the caller — and any credential the enclave presents had to
  come from somewhere, which is the same problem recursed.

## The Doorbell Solution

Invert the flow. The enclave doesn't fetch secrets; it merely announces
where it lives. The KMS client independently verifies the destination via
**remote attestation** and pushes the secrets out.

```
  Enclave Server                        KMS Client
  (confidential enclave,                (trusted operator-side process,
   boots with no secrets)                runs anywhere: laptop, EC2, ...)
        │                                     │
        │                                     │ 0. loads secrets from its
        │                                     │    backend (.env file here;
        │                                     │    Secrets Manager, Vault,
        │                                     │    etc. in production)
        │                                     │
        │  1. RING: POST /ring                │
        │     {"host": "enclave.example.dev"} │
        │────────────────────────────────────>│
        │     plain HTTP, no credentials,     │
        │     no secrets, no authority        │
        │                                     │
        │  2. ATTEST: remote attestation      │
        │<────────────────────────────────────│
        │     KMS client verifies the host    │
        │     runs the exact code released    │
        │     from ENCLAVE_REPO               │
        │                                     │
        │  3. DELIVER: POST /secrets          │
        │<────────────────────────────────────│
        │     over the attested TLS channel   │
        │     that terminates inside the      │
        │     verified enclave                │
        │                                     │
        │  4. /ring response: {"delivered"}   │
        │     (contains no secrets)           │
```

### Why this is secure

1. **The ring carries no authority.** Anyone can ring, with any hostname.
   The request is unauthenticated by design. The hostname is a delivery
   *hint*, not a claim of identity.
2. **Trust comes from attestation, not credentials.** Before delivering
   anything, the KMS client verifies — cryptographically, via the hardware
   attestation of the destination enclave — that the host runs the exact
   code published by the GitHub repo named in `ENCLAVE_REPO`. The trust
   decision is made by the secret holder, in its own configuration.
3. **Secrets only travel over the attested channel.** They are never in
   the `/ring` response. A malicious ringer can at worst trigger a delivery
   to a *legitimate, attested* enclave — which is harmless.
4. **Secrets live in enclave memory only.** Nothing is persisted. If the
   enclave restarts, it simply rings again.

Note the trust asymmetry: the KMS client is trusted *by definition* — it
already holds the secrets, so it doesn't need to be an enclave or prove
anything about itself. The pattern exists to protect delivery *into* the
enclave, whose identity must be proven.

## Components

### `kms-client/` — the secret holder (not an enclave)

A plain Go service the operator runs wherever secrets are available. Reads
secrets from a `.env`-style file at startup; the `loadSecrets` function in
`main.go` is the single integration point to swap in AWS Secrets Manager,
Vault, or any other backend.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Liveness |
| `/ring` | POST | The doorbell. Body: `{"host": "<enclave hostname>"}`. Attests the host, then delivers all secrets to its `/secrets` endpoint |

Environment:

- `ENCLAVE_REPO` (required) — GitHub repo the enclave must prove it is
  running, e.g. `example-org/doorbell-enclave-server`. **The trust decision.**
- `SECRETS_FILE` — path to the secrets file (default `secrets.env`)
- `PORT` — listen port (default `8080`)

### `enclave-server/` — the secret recipient (the enclave)

A confidential workload that boots with no secrets. On start it rings the
KMS client once, then retries every 5 minutes until the secrets arrive,
then stops ringing.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Liveness |
| `/secrets` | POST | Receives the secrets from the KMS client (arrives over the attested channel) |
| `/status` | GET | `{"received": bool, "keys": [...]}` — secret *names* only, never values |

Environment:

- `KMS_URL` — base URL of the KMS client (must be reachable from the
  enclave; see "Trying it" for the alternative when it isn't)
- `DOMAIN` — this enclave's own public hostname (injected by the platform),
  sent in the ring so the KMS client knows where to attest and deliver

## The Core Code

The entire pattern is one handler. From `kms-client/main.go`:

```go
// THE TRUST DECISION. SecureClient performs remote attestation: it
// verifies that req.Host is a genuine enclave running the exact code
// published by the ENCLAVE_REPO GitHub repo, and returns an HTTP client
// whose TLS channel terminates inside that attested enclave.
sc := client.NewSecureClient(req.Host, s.enclaveRepo)
httpClient, err := sc.HTTPClient()
if err != nil {
    http.Error(w, "enclave attestation failed: "+err.Error(), http.StatusBadGateway)
    return
}

// Deliver the secrets over the attested channel — never in the /ring
// response, so only the attested enclave ever sees them.
httpClient.Post("https://"+req.Host+"/secrets", ...)
```

`SecureClient` comes from [`tinfoil-go`](https://github.com/tinfoilsh/tinfoil-go).
It fetches the enclave's hardware attestation, verifies the measurement
against the signed release of the pinned GitHub repo, and pins the TLS
certificate to the attested enclave — so the subsequent POST cannot be
intercepted or redirected.

## Trying It

Deploy the enclave server (see below), then run the KMS client anywhere —
including your laptop:

```sh
cd kms-client
cp secrets.env.example secrets.env   # edit with your values
ENCLAVE_REPO=your-org/doorbell-enclave-server go run .
```

**If the KMS client is reachable from the enclave** (set `KMS_URL` in the
enclave's config), the enclave rings on boot and secrets arrive
automatically.

**If it isn't** (e.g. laptop behind NAT), ring on the enclave's behalf —
this works because the ring is not a privileged operation:

```sh
curl -X POST localhost:8080/ring \
  -H 'Content-Type: application/json' \
  -d '{"host": "<enclave-hostname>"}'
```

Verify delivery — names only, never values:

```sh
curl https://<enclave-hostname>/status
# {"received": true, "keys": ["API_KEY", "DATABASE_PASSWORD", "SIGNING_KEY"]}
```

To see attestation gate a delivery, ring with a host that is not the
attested enclave and watch it fail with `502 enclave attestation failed`.

## Deploying the Enclave Server

Attestation binds the enclave's identity to the GitHub repo that released
its code, so `enclave-server/` must live in its own repo:

1. Push `enclave-server/` as its own GitHub repo (e.g.
   `your-org/doorbell-enclave-server`), replacing `example-org` in
   `go.mod` and `tinfoil-config.yml` with your org.
2. Run the `Tinfoil Release` workflow. It builds the image, pins its digest
   into `tinfoil-config.yml`, measures it, and publishes a signed release —
   the artifact that attestation verifies against.
3. Deploy the enclave on Tinfoil, setting `KMS_URL` if the KMS client is
   reachable from it.
4. Point the KMS client's `ENCLAVE_REPO` at that repo.

The KMS client needs no release process, no container, and no attested
identity — it is a pure Go program. Cross-compile a static binary
(`CGO_ENABLED=0 GOOS=linux go build`) and run it anywhere, like any other
internal service.

## What This Blueprint Deliberately Leaves Out

To keep the pattern legible, this repo has **no** database, object storage,
sidecars, multi-tenant keys, or business logic. For a fuller system built on
the same pattern (per-user encryption keys delivered to consumer enclaves
for MPC-style processing), see the secret-storage example this was
distilled from.
