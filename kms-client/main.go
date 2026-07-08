// The KMS client holds secret material and delivers it to enclave servers
// that ring its doorbell.
//
// This is the "answering" side of the doorbell pattern:
//
//  1. An enclave server POSTs to /ring with nothing but its own hostname.
//     The ring is unauthenticated and carries no authority — anyone can ring.
//  2. The KMS client attests the claimed host using remote attestation,
//     verifying that it runs the expected code from ENCLAVE_REPO.
//  3. Only if attestation succeeds, the KMS client dials OUT to the enclave
//     server and delivers the secret over the attested TLS channel.
//
// The secret is never returned in the /ring response. Trust comes entirely
// from the outbound attestation of the destination, not from any credential
// on the inbound request.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

type Server struct {
	secret      []byte // the secret material to deliver (in-memory only)
	enclaveRepo string // GitHub repo the enclave server must be running (hardcoded trust decision)
}

func main() {
	enclaveRepo := os.Getenv("ENCLAVE_REPO")
	if enclaveRepo == "" {
		log.Fatal("ENCLAVE_REPO is required (e.g. your-org/doorbell-enclave-server)")
	}

	// Generate the demo secret at boot. In a real deployment this would be
	// key material loaded from an HSM, a sealed store, or operator-provided
	// secrets. It exists in enclave memory only.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Fatalf("generating secret: %v", err)
	}

	srv := &Server{secret: secret, enclaveRepo: enclaveRepo}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", srv.handleHealth)
	mux.HandleFunc("GET /secret_info", srv.handleSecretInfo)
	mux.HandleFunc("POST /ring", srv.handleRing)

	log.Printf("kms-client listening on :8089 (secret fingerprint %s, trusting %s)",
		fingerprint(secret), enclaveRepo)
	log.Fatal(http.ListenAndServe(":8089", mux))
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// /secret_info exposes a SHA-256 fingerprint of the secret — never the secret
// itself — so an observer can verify end-to-end delivery by comparing it with
// the enclave server's /status.
func (s *Server) handleSecretInfo(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"fingerprint": fingerprint(s.secret)})
}

type ringRequest struct {
	// Host is the enclave server's public hostname. It is a delivery hint,
	// not a claim of identity: a malicious ringer can only trigger delivery
	// to a host that passes attestation against ENCLAVE_REPO.
	Host string `json:"host"`
}

// /ring is the doorbell. It attests the claimed host and, on success,
// delivers the secret to the host's /secrets endpoint over attested TLS.
func (s *Server) handleRing(w http.ResponseWriter, r *http.Request) {
	var req ringRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Host == "" {
		http.Error(w, "host is required", http.StatusBadRequest)
		return
	}

	// THE TRUST DECISION. SecureClient performs remote attestation: it
	// verifies that req.Host is a genuine enclave running the exact code
	// published by the ENCLAVE_REPO GitHub repo, and returns an HTTP client
	// whose TLS channel terminates inside that attested enclave.
	sc := client.NewSecureClient(req.Host, s.enclaveRepo)
	httpClient, err := sc.HTTPClient()
	if err != nil {
		log.Printf("/ring: attestation FAILED for %s (expected %s): %v", req.Host, s.enclaveRepo, err)
		http.Error(w, "enclave attestation failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	// Deliver the secret over the attested channel — never in the /ring
	// response, so only the attested enclave ever sees it.
	body, _ := json.Marshal(map[string]string{
		"secret": base64.StdEncoding.EncodeToString(s.secret),
	})
	deliverReq, _ := http.NewRequestWithContext(r.Context(),
		http.MethodPost, "https://"+req.Host+"/secrets", bytes.NewReader(body))
	deliverReq.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(deliverReq)
	if err != nil {
		http.Error(w, "delivery failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("enclave server returned %d", resp.StatusCode), http.StatusBadGateway)
		return
	}

	log.Printf("/ring: attested %s (%s) and delivered secret", req.Host, s.enclaveRepo)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "delivered"})
}

func fingerprint(secret []byte) string {
	sum := sha256.Sum256(secret)
	return "sha256:" + hex.EncodeToString(sum[:])
}
