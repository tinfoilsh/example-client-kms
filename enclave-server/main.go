// The enclave server is a workload that needs a secret it does not have at
// boot. It obtains one by ringing the KMS client's doorbell.
//
// This is the "ringing" side of the doorbell pattern:
//
//  1. On a loop, the enclave server POSTs {"host": <its own hostname>} to the
//     KMS client's /ring endpoint. The ring carries no secrets and no
//     credentials in either direction.
//  2. The KMS client attests this enclave (verifying it runs the expected
//     code from the expected GitHub repo) and, on success, dials back in and
//     POSTs the secret to /secrets over the attested TLS channel.
//  3. Once the secret arrives, the ring loop stops. The secret is held in
//     memory only.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type Server struct {
	mu     sync.RWMutex
	secret []byte // delivered secret (in-memory only, empty until delivery)

	kmsURL string // base URL of the KMS client, e.g. https://kms.example.dev
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
	Secret string `json:"secret"` // base64
}

// /secrets accepts the secret delivered by the KMS client. The KMS client
// only calls this endpoint after attesting this enclave, and the request
// arrives over the attested TLS channel it established.
func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	var req deliverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	secret, err := base64.StdEncoding.DecodeString(req.Secret)
	if err != nil || len(secret) == 0 {
		http.Error(w, "invalid base64 secret", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.secret = secret
	s.mu.Unlock()

	log.Printf("/secrets: received secret (fingerprint %s)", fingerprint(secret))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "received"})
}

// /status reports whether the secret has been delivered, and its SHA-256
// fingerprint — never the secret itself. Compare with the KMS client's
// /secret_info to verify end-to-end delivery.
func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	secret := s.secret
	s.mu.RUnlock()

	resp := map[string]any{"received": len(secret) > 0}
	if len(secret) > 0 {
		resp["fingerprint"] = fingerprint(secret)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ringLoop rings the KMS client's doorbell until the secret arrives.
// The ring itself is a plain HTTP POST containing only this enclave's
// hostname — delivery happens out-of-band via /secrets after the KMS
// client attests us.
func (s *Server) ringLoop(ctx context.Context) {
	if s.kmsURL == "" || s.domain == "" {
		log.Printf("KMS_URL or DOMAIN not set, skipping ring loop")
		return
	}

	ringBody, _ := json.Marshal(map[string]string{"host": s.domain})
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.RLock()
			received := len(s.secret) > 0
			s.mu.RUnlock()
			if received {
				log.Printf("ring: secret received, stopping ring loop")
				return
			}

			resp, err := http.Post(s.kmsURL+"/ring", "application/json", bytes.NewReader(ringBody))
			if err != nil {
				log.Printf("ring: %v", err)
				continue
			}
			resp.Body.Close()
			log.Printf("ring: KMS client returned %d", resp.StatusCode)
		}
	}
}

func fingerprint(secret []byte) string {
	sum := sha256.Sum256(secret)
	return "sha256:" + hex.EncodeToString(sum[:])
}
