# The Doorbell Pattern: Attested Secret Delivery Between Enclaves

A minimal blueprint for delivering secrets to enclaves using the **doorbell
pattern**: an enclave that needs a secret "rings a doorbell", and the secret
holder — after verifying the enclave via remote attestation — pushes the
secret to it over an attested TLS channel.

This repo contains exactly two services and nothing else. It exists to
exemplify the pattern in isolation.

## The Problem

An enclave server boots with no secrets. It needs key material (API keys,
encryption keys, credentials) but:

- Baking secrets into the image would expose them to anyone with the image
  and would show up in the attested measurement.
- Letting the enclave *pull* secrets would require the secret holder to
  authenticate the caller — and any credential the enclave presents had to
  come from somewhere, which is the same problem recursed.

## The Doorbell Solution

Invert the flow. The enclave doesn't fetch the secret; it merely announces
where it lives. The secret holder independently verifies the destination via
**remote attestation** and pushes the secret out.

```
  Enclave Server                        KMS Client
  (needs a secret)                      (holds the secret)
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
        │     (contains no secret)            │
```

### Why this is secure

1. **The ring carries no authority.** Anyone can ring, with any hostname.
   The request is unauthenticated by design. The hostname is a delivery
   *hint*, not a claim of identity.
2. **Trust comes from attestation, not credentials.** Before delivering
   anything, the KMS client verifies — cryptographically, via the hardware
   attestation of the destination enclave — that the host runs the exact
   code published by the GitHub repo named in `ENCLAVE_REPO`. That repo name
   is pinned in the KMS client's own configuration: the trust decision is
   made by the secret holder at deploy time and is itself auditable.
3. **The secret only travels over the attested channel.** It is never in
   the `/ring` response. A malicious ringer can at worst trigger a delivery
   to a *legitimate, attested* enclave — which is harmless.
4. **Secrets live in memory only.** Neither side persists the secret. If
   the enclave server restarts, it simply rings again.

## Components

### `kms-client/` — the secret holder

Plays the role a KMS client would in a production system: it has the secret
and decides who gets it.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Liveness |
| `/ring` | POST | The doorbell. Body: `{"host": "<enclave hostname>"}`. Attests the host, then delivers the secret to its `/secrets` endpoint |
| `/secret_info` | GET | SHA-256 fingerprint of the secret (never the secret) for verifying delivery |

Environment:

- `ENCLAVE_REPO` (required) — GitHub repo the enclave server must prove it
  is running, e.g. `example-org/doorbell-enclave-server`. **This is the
  trust decision.**

The demo secret is generated randomly at boot. In a real deployment this
would be key material from an HSM, a sealed store, or operator-provisioned
secrets — the delivery pattern is identical.

### `enclave-server/` — the secret recipient

A workload that boots with no secrets and obtains one by ringing.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Liveness |
| `/secrets` | POST | Receives the secret from the KMS client (arrives over the attested channel) |
| `/status` | GET | `{"received": bool, "fingerprint": "sha256:..."}` — proof of delivery without exposure |

Environment:

- `KMS_URL` — base URL of the KMS client, e.g. `https://doorbell-kms-client.tinfoil.containers.tinfoil.dev`
- `DOMAIN` — this enclave's own public hostname (injected by the platform),
  sent in the ring so the KMS client knows where to attest and deliver

On boot it rings every 15 seconds until the secret arrives, then stops.

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

// Deliver the secret over the attested channel — never in the /ring
// response, so only the attested enclave ever sees it.
httpClient.Post("https://"+req.Host+"/secrets", ...)
```

`SecureClient` comes from [`tinfoil-go`](https://github.com/tinfoilsh/tinfoil-go).
It fetches the enclave's hardware attestation, verifies the measurement
against the signed release of the pinned GitHub repo, and pins the TLS
certificate to the attested enclave — so the subsequent POST cannot be
intercepted or redirected.

## Verifying the Pattern (demo)

With both enclaves deployed, `demo/demo.sh` walks through four checks:

```sh
./demo/demo.sh <kms-client-host> <enclave-server-host>
```

1. **Delivery happened, secret never exposed** — the fingerprint from the
   KMS client's `/secret_info` matches the enclave server's `/status`.
2. **Anyone can ring** — a ring from your laptop (naming the legitimate
   enclave) succeeds. The ring is not a privileged operation.
3. **Attestation gates delivery** — a ring naming an unattested host fails
   with `502 attestation failed`. Nothing is delivered.
4. **The response carries no secret** — the `/ring` response body is
   inspected: it contains only `{"status": "delivered"}`.

## Deploying

Each service directory is designed to be pushed as **its own GitHub repo**.
This matters: attestation binds an enclave's identity to the repo that
released its code, so the two services cannot share one repo.

1. Push `kms-client/` and `enclave-server/` as two repos (e.g.
   `your-org/doorbell-kms-client`, `your-org/doorbell-enclave-server`).
2. Replace `example-org` with your org in each `go.mod`,
   `tinfoil-config.yml`, and set `ENCLAVE_REPO` in the KMS client's config
   to the enclave server's repo.
3. Run the `Tinfoil Release` workflow in each repo. It builds the image,
   pins its digest into `tinfoil-config.yml`, measures it, and publishes a
   signed release — the artifact that attestation verifies against.
4. Deploy both enclaves on Tinfoil. Set `KMS_URL` on the enclave server to
   the KMS client's deployed hostname.

The enclave server starts ringing on boot; within ~15 seconds of both being
up, the secret is delivered.

## What This Blueprint Deliberately Leaves Out

To keep the pattern legible, this repo has **no** database, object storage,
sidecars, multi-tenant keys, or business logic. For a fuller system built on
the same pattern (per-user encryption keys delivered to consumer enclaves for
MPC-style processing), see the secret-storage example this was distilled from.
