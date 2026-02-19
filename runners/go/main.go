package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/usetero/policy-go"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// ─── Stats output ────────────────────────────────────────────────────

type StatsOutput struct {
	Policies []PolicyHit `json:"policies"`
}

type PolicyHit struct {
	PolicyID string `json:"policy_id"`
	Hits     uint64 `json:"hits"`
	Misses   uint64 `json:"misses,omitempty"`
}

func writeStats(path string, registry *policy.PolicyRegistry) error {
	stats := registry.CollectStats()
	var output StatsOutput
	for _, s := range stats {
		if s.MatchHits > 0 || s.MatchMisses > 0 {
			output.Policies = append(output.Policies, PolicyHit{
				PolicyID: s.PolicyID,
				Hits:     s.MatchHits,
				Misses:   s.MatchMisses,
			})
		}
	}
	if output.Policies == nil {
		output.Policies = []PolicyHit{}
	}
	sort.Slice(output.Policies, func(i, j int) bool {
		return output.Policies[i].PolicyID < output.Policies[j].PolicyID
	})
	data, err := json.Marshal(output)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ─── Signal processing ──────────────────────────────────────────────

var marshaler = protojson.MarshalOptions{
	EmitUnpopulated: true,
}

func processLogs(eng *policy.PolicyEngine, registry *policy.PolicyRegistry, inputData []byte) ([]byte, error) {
	var data logspb.LogsData
	if err := protojson.Unmarshal(inputData, &data); err != nil {
		return nil, fmt.Errorf("unmarshal logs: %w", err)
	}

	// Reset stats before evaluation
	registry.CollectStats()

	for _, rl := range data.ResourceLogs {
		for _, sl := range rl.ScopeLogs {
			kept := sl.LogRecords[:0]
			for _, rec := range sl.LogRecords {
				ctx := &LogContext{
					Record:   rec,
					Resource: rl.Resource,
					Scope:    sl.Scope,
				}
				result := policy.EvaluateLog(eng, ctx, OTelLogMatcher, policy.WithLogTransform(OTelLogTransformer))
				if result != policy.ResultDrop {
					kept = append(kept, rec)
				}
			}
			sl.LogRecords = kept
		}
	}

	// Prune empty scope containers
	for _, rl := range data.ResourceLogs {
		kept := rl.ScopeLogs[:0]
		for _, sl := range rl.ScopeLogs {
			if len(sl.LogRecords) > 0 {
				kept = append(kept, sl)
			}
		}
		rl.ScopeLogs = kept
	}

	// Prune empty resource containers
	kept := data.ResourceLogs[:0]
	for _, rl := range data.ResourceLogs {
		if len(rl.ScopeLogs) > 0 {
			kept = append(kept, rl)
		}
	}
	data.ResourceLogs = kept

	return marshaler.Marshal(&data)
}

func processMetrics(eng *policy.PolicyEngine, registry *policy.PolicyRegistry, inputData []byte) ([]byte, error) {
	var data metricspb.MetricsData
	if err := protojson.Unmarshal(inputData, &data); err != nil {
		return nil, fmt.Errorf("unmarshal metrics: %w", err)
	}

	registry.CollectStats()

	for _, rm := range data.ResourceMetrics {
		for _, sm := range rm.ScopeMetrics {
			kept := sm.Metrics[:0]
			for _, m := range sm.Metrics {
				ctx := &MetricContext{
					Metric:              m,
					DatapointAttributes: getDatapointAttrs(m),
					Resource:            rm.Resource,
					Scope:               sm.Scope,
				}
				result := policy.EvaluateMetric(eng, ctx, OTelMetricMatcher)
				if result != policy.ResultDrop {
					kept = append(kept, m)
				}
			}
			sm.Metrics = kept
		}
	}

	for _, rm := range data.ResourceMetrics {
		kept := rm.ScopeMetrics[:0]
		for _, sm := range rm.ScopeMetrics {
			if len(sm.Metrics) > 0 {
				kept = append(kept, sm)
			}
		}
		rm.ScopeMetrics = kept
	}

	keptRM := data.ResourceMetrics[:0]
	for _, rm := range data.ResourceMetrics {
		if len(rm.ScopeMetrics) > 0 {
			keptRM = append(keptRM, rm)
		}
	}
	data.ResourceMetrics = keptRM

	return marshaler.Marshal(&data)
}

func processTraces(eng *policy.PolicyEngine, registry *policy.PolicyRegistry, inputData []byte) ([]byte, error) {
	var data tracepb.TracesData
	if err := protojson.Unmarshal(inputData, &data); err != nil {
		return nil, fmt.Errorf("unmarshal traces: %w", err)
	}

	registry.CollectStats()

	for _, rs := range data.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			kept := ss.Spans[:0]
			for _, span := range ss.Spans {
				ctx := &TraceContext{
					Span:     span,
					Resource: rs.Resource,
					Scope:    ss.Scope,
				}
				result := policy.EvaluateTrace(eng, ctx, OTelTraceMatcher)
				if result != policy.ResultDrop {
					kept = append(kept, span)
				}
			}
			ss.Spans = kept
		}
	}

	for _, rs := range data.ResourceSpans {
		kept := rs.ScopeSpans[:0]
		for _, ss := range rs.ScopeSpans {
			if len(ss.Spans) > 0 {
				kept = append(kept, ss)
			}
		}
		rs.ScopeSpans = kept
	}

	keptRS := data.ResourceSpans[:0]
	for _, rs := range data.ResourceSpans {
		if len(rs.ScopeSpans) > 0 {
			keptRS = append(keptRS, rs)
		}
	}
	data.ResourceSpans = keptRS

	return marshaler.Marshal(&data)
}

// ─── Main ────────────────────────────────────────────────────────────

func main() {
	policiesPath := flag.String("policies", "", "path to policies.json")
	serverURL := flag.String("server", "", "HTTP sync endpoint URL (e.g. http://localhost:8080/v1/policy/sync)")
	grpcAddr := flag.String("grpc", "", "gRPC server address (e.g. localhost:9090)")
	inputPath := flag.String("input", "", "path to input.json")
	outputPath := flag.String("output", "", "path to output.json")
	statsPath := flag.String("stats", "", "path to stats.json")
	signalFlag := flag.String("signal", "", "signal type: log, metric, trace")
	flag.Parse()

	if *inputPath == "" || *outputPath == "" || *signalFlag == "" {
		fmt.Fprintf(os.Stderr, "usage: runner-go (--policies <path> | --server <url> | --grpc <addr>) --input <path> --output <path> --signal <log|metric|trace> [--stats <path>]\n")
		os.Exit(1)
	}

	remoteMode := *serverURL != "" || *grpcAddr != ""
	if !remoteMode && (*policiesPath == "" || *statsPath == "") {
		fmt.Fprintf(os.Stderr, "usage: runner-go --policies <path> --input <path> --output <path> --stats <path> --signal <log|metric|trace>\n")
		os.Exit(1)
	}

	// Load policies
	registry := policy.NewPolicyRegistry()
	var provider policy.PolicyProvider
	switch {
	case *serverURL != "":
		provider = policy.NewHttpProvider(*serverURL,
			policy.WithContentType(policy.ContentTypeJSON),
			policy.WithHTTPPollInterval(60*time.Second),
		)
	case *grpcAddr != "":
		provider = policy.NewGrpcProvider(*grpcAddr,
			policy.WithGrpcInsecure(),
			policy.WithGrpcPollInterval(60*time.Second),
		)
	default:
		provider = policy.NewFileProvider(*policiesPath)
	}

	handle, err := registry.Register(provider)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load policies: %v\n", err)
		os.Exit(1)
	}
	defer handle.Unregister()

	// Read input
	inputData, err := os.ReadFile(*inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read input: %v\n", err)
		os.Exit(1)
	}

	eng := policy.NewPolicyEngine(registry)

	var output []byte
	switch *signalFlag {
	case "log":
		output, err = processLogs(eng, registry, inputData)
	case "metric":
		output, err = processMetrics(eng, registry, inputData)
	case "trace":
		output, err = processTraces(eng, registry, inputData)
	default:
		fmt.Fprintf(os.Stderr, "unknown signal: %s\n", *signalFlag)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Write output
	if err := os.WriteFile(*outputPath, output, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write output: %v\n", err)
		os.Exit(1)
	}

	if remoteMode {
		// In remote mode, trigger a second sync to report stats back to the server.
		// Load() performs a sync which includes policy_statuses from CollectStats.
		if _, err := provider.Load(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to sync stats: %v\n", err)
		}
	} else {
		// In file mode, write stats locally
		if err := writeStats(*statsPath, registry); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write stats: %v\n", err)
			os.Exit(1)
		}
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────

func collectMatchedPolicies(registry *policy.PolicyRegistry) []string {
	stats := registry.CollectStats()
	var matched []string
	for _, s := range stats {
		if s.MatchHits > 0 {
			matched = append(matched, s.PolicyID)
		}
	}
	sort.Strings(matched)
	if matched == nil {
		matched = []string{}
	}
	return matched
}
