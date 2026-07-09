// The enclave server is the secret-receiving side of the doorbell pattern:
// a confidential workload that boots with no secrets and obtains them by
// ringing the KMS client's doorbell.
//
//  1. On start, it POSTs {"host": <its own hostname>} to the KMS client's
//     /ring endpoint. The ring carries no secrets and no credentials in
//     either direction. If secrets don't arrive, it retries every 5 minutes.
//  2. The KMS client attests this enclave — verifying it runs the expected
//     code from the expected GitHub repo — and, on success, POSTs the
//     secrets to /secrets over the attested TLS channel it established.
//  3. Once the secrets arrive, the ring loop stops. Secrets are held in
//     memory only; on restart the enclave simply rings again.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

const ringRetryInterval = 5 * time.Minute

type Server struct {
	mu      sync.RWMutex
	secrets map[string]string // delivered secrets (in-memory only, empty until delivery)

	kmsURL string // base URL of the KMS client, e.g. https://kms.internal.example.com
	domain string // this enclave's own public hostname, sent in the ring
}

func main() {
	srv := &Server{
		kmsURL: os.Getenv("KMS_URL"),
		domain: os.Getenv("DOMAIN"),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.ringLoop(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", srv.handleHealth)
	mux.HandleFunc("POST /secrets", srv.handleSecrets)
	mux.HandleFunc("GET /status", srv.handleStatus)

	log.Printf("enclave-server listening on :8089")
	log.Fatal(http.ListenAndServe(":8089", mux))
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

type deliverRequest struct {
	Secrets map[string]string `json:"secrets"`
}

// /secrets accepts the secrets delivered by the KMS client. The KMS client
// only calls this endpoint after attesting this enclave, and the request
// arrives over the attested TLS channel it established.
func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	var req deliverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.Secrets) == 0 {
		http.Error(w, "no secrets in payload", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.secrets = req.Secrets
	s.mu.Unlock()

	// From here, the actual workload would read its configuration from
	// s.secrets instead of the environment.
	log.Printf("/secrets: received %d secrets: %v", len(req.Secrets), keyNames(req.Secrets))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"received": len(req.Secrets)})
}

// /status reports whether secrets have been delivered and their names —
// never their values.
func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	names := keyNames(s.secrets)
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"received": len(names) > 0,
		"keys":     names,
	})
}

// ringLoop rings the KMS client's doorbell once on start, then retries
// every 5 minutes until the secrets arrive. The ring itself is a plain
// HTTP POST containing only this enclave's hostname — delivery happens
// out-of-band via /secrets after the KMS client attests us.
func (s *Server) ringLoop(ctx context.Context) {
	if s.kmsURL == "" || s.domain == "" {
		log.Printf("KMS_URL or DOMAIN not set, skipping ring loop")
		return
	}

	ringBody, _ := json.Marshal(map[string]string{"host": s.domain})
	for {
		s.mu.RLock()
		received := len(s.secrets) > 0
		s.mu.RUnlock()
		if received {
			log.Printf("ring: secrets received, stopping ring loop")
			return
		}

		resp, err := http.Post(s.kmsURL+"/ring", "application/json", bytes.NewReader(ringBody))
		if err != nil {
			log.Printf("ring: %v (retrying in %v)", err, ringRetryInterval)
		} else {
			resp.Body.Close()
			log.Printf("ring: KMS client returned %d", resp.StatusCode)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(ringRetryInterval):
		}
	}
}

func keyNames(secrets map[string]string) []string {
	names := make([]string, 0, len(secrets))
	for k := range secrets {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
