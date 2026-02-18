package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/usetero/policy-go"
	policyv1 "github.com/usetero/policy-go/proto/tero/policy/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// ─── Policy store ────────────────────────────────────────────────────

type policyStore struct {
	mu       sync.RWMutex
	policies []*policyv1.Policy
	hash     string

	// Accumulated stats from client sync requests
	stats map[string]int64 // policy_id -> match_hits
}

func newPolicyStore() *policyStore {
	return &policyStore{
		stats: make(map[string]int64),
	}
}

func (s *policyStore) loadFile(path string) error {
	provider := policy.NewFileProvider(path)
	policies, err := provider.Load()
	if err != nil {
		return fmt.Errorf("load %s: %w", path, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.policies = append(s.policies, policies...)

	// Compute hash over all policy IDs
	h := sha256.New()
	for _, p := range s.policies {
		h.Write([]byte(p.GetId()))
	}
	s.hash = fmt.Sprintf("%x", h.Sum(nil))

	return nil
}

func (s *policyStore) recordStats(statuses []*policyv1.PolicySyncStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range statuses {
		if st.GetMatchHits() > 0 {
			s.stats[st.GetId()] += st.GetMatchHits()
		}
	}
}

type policyHit struct {
	PolicyID string `json:"policy_id"`
	Hits     int64  `json:"hits"`
}

type statsOutput struct {
	Policies []policyHit `json:"policies"`
}

func (s *policyStore) getStats() statsOutput {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out statsOutput
	for id, hits := range s.stats {
		out.Policies = append(out.Policies, policyHit{PolicyID: id, Hits: hits})
	}
	if out.Policies == nil {
		out.Policies = []policyHit{}
	}
	sort.Slice(out.Policies, func(i, j int) bool {
		return out.Policies[i].PolicyID < out.Policies[j].PolicyID
	})
	return out
}

func (s *policyStore) sync(req *policyv1.SyncRequest) *policyv1.SyncResponse {
	// Record any stats from the client
	if len(req.GetPolicyStatuses()) > 0 {
		s.recordStats(req.GetPolicyStatuses())
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return &policyv1.SyncResponse{
		Policies:                       s.policies,
		Hash:                           s.hash,
		SyncTimestampUnixNano:          uint64(time.Now().UnixNano()),
		RecommendedSyncIntervalSeconds: 30,
		SyncType:                       policyv1.SyncType_SYNC_TYPE_FULL,
	}
}

// ─── gRPC service ────────────────────────────────────────────────────

type grpcService struct {
	policyv1.UnimplementedPolicyServiceServer
	store *policyStore
}

func (s *grpcService) Sync(_ context.Context, req *policyv1.SyncRequest) (*policyv1.SyncResponse, error) {
	return s.store.sync(req), nil
}

// ─── HTTP handlers ───────────────────────────────────────────────────

func syncHandler(store *policyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}

		ct := r.Header.Get("Content-Type")
		var req policyv1.SyncRequest

		switch ct {
		case "application/x-protobuf":
			if err := proto.Unmarshal(body, &req); err != nil {
				http.Error(w, "unmarshal protobuf: "+err.Error(), http.StatusBadRequest)
				return
			}
		default:
			// Use protojson to decode — handles both camelCase and snake_case field names,
			// and string-encoded int64/uint64 per proto3 JSON spec.
			if err := protojson.Unmarshal(body, &req); err != nil {
				http.Error(w, "decode json: "+err.Error(), http.StatusBadRequest)
				return
			}
		}

		resp := store.sync(&req)

		accept := r.Header.Get("Accept")
		switch accept {
		case "application/x-protobuf":
			data, err := proto.Marshal(resp)
			if err != nil {
				http.Error(w, "marshal protobuf: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/x-protobuf")
			w.Write(data)
		default:
			data, err := protojson.MarshalOptions{EmitDefaultValues: true, UseEnumNumbers: true}.Marshal(resp)
			if err != nil {
				http.Error(w, "marshal json: "+err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(data)
		}
	}
}

func statsHandler(store *policyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(store.getStats())
	}
}

// ─── Main ────────────────────────────────────────────────────────────

func main() {
	policiesPath := flag.String("policies", "", "path to policies.json")
	httpPort := flag.Int("http-port", 0, "HTTP port (0 = auto)")
	grpcPort := flag.Int("grpc-port", 0, "gRPC port (0 = auto)")
	flag.Parse()

	if *policiesPath == "" {
		fmt.Fprintf(os.Stderr, "usage: conformance-server --policies <path> [--http-port N] [--grpc-port N]\n")
		os.Exit(1)
	}

	store := newPolicyStore()
	if err := store.loadFile(*policiesPath); err != nil {
		log.Fatalf("failed to load policies: %v", err)
	}

	var wg sync.WaitGroup
	var httpServer *http.Server
	shutdownCh := make(chan struct{})

	// Start gRPC server
	grpcLis, err := net.Listen("tcp", fmt.Sprintf(":%d", *grpcPort))
	if err != nil {
		log.Fatalf("failed to listen for gRPC: %v", err)
	}
	grpcSrv := grpc.NewServer()
	policyv1.RegisterPolicyServiceServer(grpcSrv, &grpcService{store: store})

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := grpcSrv.Serve(grpcLis); err != nil {
			log.Printf("gRPC server error: %v", err)
		}
	}()

	// Start HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/policy/sync", syncHandler(store))
	mux.HandleFunc("/stats", statsHandler(store))
	mux.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
		go func() { close(shutdownCh) }()
	})

	httpLis, err := net.Listen("tcp", fmt.Sprintf(":%d", *httpPort))
	if err != nil {
		log.Fatalf("failed to listen for HTTP: %v", err)
	}
	httpServer = &http.Server{Handler: mux}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := httpServer.Serve(httpLis); err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Print ports for test harness to capture
	fmt.Printf("HTTP_PORT=%d\n", httpLis.Addr().(*net.TCPAddr).Port)
	fmt.Printf("GRPC_PORT=%d\n", grpcLis.Addr().(*net.TCPAddr).Port)

	// Wait for shutdown signal
	<-shutdownCh
	httpServer.Shutdown(context.Background())
	grpcSrv.GracefulStop()
	wg.Wait()
}
