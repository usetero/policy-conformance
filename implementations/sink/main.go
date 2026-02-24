package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
)

// ─── Accumulated OTLP data ──────────────────────────────────────────

type sink struct {
	mu   sync.Mutex
	logs []json.RawMessage // resourceLogs entries
	metrics []json.RawMessage // resourceMetrics entries
	traces  []json.RawMessage // resourceSpans entries
}

func (s *sink) appendLogs(resources []json.RawMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = append(s.logs, resources...)
}

func (s *sink) appendMetrics(resources []json.RawMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.metrics = append(s.metrics, resources...)
}

func (s *sink) appendTraces(resources []json.RawMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.traces = append(s.traces, resources...)
}

func (s *sink) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = nil
	s.metrics = nil
	s.traces = nil
}

func (s *sink) hasData() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.logs) > 0 || len(s.metrics) > 0 || len(s.traces) > 0
}

func (s *sink) output() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make(map[string]any)
	if len(s.logs) > 0 {
		out["resourceLogs"] = s.logs
	}
	if len(s.metrics) > 0 {
		out["resourceMetrics"] = s.metrics
	}
	if len(s.traces) > 0 {
		out["resourceSpans"] = s.traces
	}
	return out
}

// ─── HTTP handlers ──────────────────────────────────────────────────

func ingestHandler(s *sink, field string, appendFn func([]json.RawMessage)) http.HandlerFunc {
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

		// Parse the top-level object and extract the resource array
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(body, &envelope); err != nil {
			http.Error(w, "decode json: "+err.Error(), http.StatusBadRequest)
			return
		}

		raw, ok := envelope[field]
		if !ok || len(raw) == 0 {
			// Empty payload — acknowledge but don't accumulate
			w.WriteHeader(http.StatusOK)
			return
		}

		var resources []json.RawMessage
		if err := json.Unmarshal(raw, &resources); err != nil {
			http.Error(w, "decode resources: "+err.Error(), http.StatusBadRequest)
			return
		}

		appendFn(resources)
		w.WriteHeader(http.StatusOK)
	}
}

func outputHandler(s *sink) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.output())
	}
}

func resetHandler(s *sink) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.reset()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}
}

// ─── Main ───────────────────────────────────────────────────────────

func main() {
	port := flag.Int("port", 0, "listen port (0 = auto)")
	flag.Parse()

	s := &sink{}

	mux := http.NewServeMux()

	// OTLP ingest endpoints
	mux.HandleFunc("/v1/logs", ingestHandler(s, "resourceLogs", s.appendLogs))
	mux.HandleFunc("/v1/metrics", ingestHandler(s, "resourceMetrics", s.appendMetrics))
	mux.HandleFunc("/v1/traces", ingestHandler(s, "resourceSpans", s.appendTraces))

	// Control endpoints
	mux.HandleFunc("/has-data", func(w http.ResponseWriter, r *http.Request) {
		if s.hasData() {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("true"))
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	})
	mux.HandleFunc("/output", outputHandler(s))
	mux.HandleFunc("/reset", resetHandler(s))

	shutdownCh := make(chan struct{})
	mux.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
		go func() { close(shutdownCh) }()
	})

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	server := &http.Server{Handler: mux}

	go func() {
		if err := server.Serve(lis); err != http.ErrServerClosed {
			log.Printf("server error: %v", err)
		}
	}()

	// Print port for harness to capture via FIFO
	fmt.Printf("SINK_PORT=%d\n", lis.Addr().(*net.TCPAddr).Port)

	<-shutdownCh
	server.Shutdown(context.Background())
}
