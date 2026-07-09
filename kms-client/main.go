// The KMS client is the secret-holding side of the doorbell pattern.
//
// It is NOT an enclave. It is a trusted service run by the end user,
// anywhere secrets are available: a laptop, an EC2 instance, a container
// next to your secret manager. Its job:
//
//  1. Load secrets from a backend. Here that backend is a .env file — the
//     simplest possible interface. To use AWS Secrets Manager, Vault, or
//     anything else, replace loadSecrets; the delivery pattern is unchanged.
//  2. Listen for doorbell rings: POST /ring {"host": "<enclave hostname>"}.
//     The ring is unauthenticated and carries no authority — anyone can ring.
//  3. On each ring, remote-attest the claimed host, verifying it is a
//     genuine enclave running the exact code released from the ENCLAVE_REPO
//     GitHub repo. Only then, push the secrets to the enclave's /secrets
//     endpoint over the attested TLS channel.
//
// Secrets are never returned in the /ring response. Trust comes entirely
// from the outbound attestation of the destination, not from any credential
// on the inbound request.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/tinfoilsh/tinfoil-go/verifier/client"
)

type Server struct {
	secrets     map[string]string // loaded from the secret backend, held in memory
	enclaveRepo string            // GitHub repo the enclave must be running (the trust decision)
}

func main() {
	enclaveRepo := os.Getenv("ENCLAVE_REPO")
	if enclaveRepo == "" {
		log.Fatal("ENCLAVE_REPO is required (e.g. your-org/doorbell-enclave-server)")
	}

	secretsFile := os.Getenv("SECRETS_FILE")
	if secretsFile == "" {
		secretsFile = "secrets.env"
	}
	secrets, err := loadSecrets(secretsFile)
	if err != nil {
		log.Fatalf("loading secrets: %v", err)
	}
	if len(secrets) == 0 {
		log.Fatalf("no secrets found in %s", secretsFile)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &Server{secrets: secrets, enclaveRepo: enclaveRepo}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", srv.handleHealth)
	mux.HandleFunc("POST /ring", srv.handleRing)

	log.Printf("kms-client listening on :%s (%d secrets loaded: %s; trusting %s)",
		port, len(secrets), strings.Join(keyNames(secrets), ", "), enclaveRepo)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

// loadSecrets is the secret backend interface. This implementation reads
// KEY=VALUE pairs from a .env-style file (blank lines and # comments are
// ignored). Replace this function to source secrets from AWS Secrets
// Manager, Vault, GCP Secret Manager, etc. — nothing else needs to change.
func loadSecrets(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	secrets := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("malformed line (expected KEY=VALUE): %q", line)
		}
		secrets[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return secrets, scanner.Err()
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

type ringRequest struct {
	// Host is the enclave's public hostname. It is a delivery hint, not a
	// claim of identity: a malicious ringer can only trigger delivery to a
	// host that passes attestation against ENCLAVE_REPO.
	Host string `json:"host"`
}

// /ring is the doorbell. It attests the claimed host and, on success,
// delivers the secrets to the host's /secrets endpoint over attested TLS.
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

	// Deliver the secrets over the attested channel — never in the /ring
	// response, so only the attested enclave ever sees them.
	body, _ := json.Marshal(map[string]any{"secrets": s.secrets})
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
		http.Error(w, fmt.Sprintf("enclave returned %d", resp.StatusCode), http.StatusBadGateway)
		return
	}

	log.Printf("/ring: attested %s (%s) and delivered %d secrets", req.Host, s.enclaveRepo, len(s.secrets))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "delivered"})
}

func keyNames(secrets map[string]string) []string {
	names := make([]string, 0, len(secrets))
	for k := range secrets {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
