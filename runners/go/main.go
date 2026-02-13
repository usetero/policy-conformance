package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/usetero/policy-go"
)

// Input represents the conformance test input file.
type Input struct {
	SignalType string          `json:"signal_type"`
	Records    json.RawMessage `json:"records"`
}

// LogRecord is a log record from the input file.
type LogRecord struct {
	ID                 string         `json:"id"`
	Body               string         `json:"body"`
	SeverityText       string         `json:"severity_text"`
	TraceID            string         `json:"trace_id"`
	SpanID             string         `json:"span_id"`
	Attributes         map[string]any `json:"attributes"`
	ResourceAttributes map[string]any `json:"resource_attributes"`
	ScopeAttributes    map[string]any `json:"scope_attributes"`
}

// MetricRecord is a metric record from the input file.
type MetricRecord struct {
	ID                     string         `json:"id"`
	Name                   string         `json:"name"`
	Description            string         `json:"description"`
	Unit                   string         `json:"unit"`
	MetricType             string         `json:"metric_type"`
	AggregationTemporality string         `json:"aggregation_temporality"`
	DatapointAttributes    map[string]any `json:"datapoint_attributes"`
	ResourceAttributes     map[string]any `json:"resource_attributes"`
	ScopeAttributes        map[string]any `json:"scope_attributes"`
}

// TraceRecord is a trace/span record from the input file.
type TraceRecord struct {
	ID                 string         `json:"id"`
	Name               string         `json:"name"`
	TraceID            string         `json:"trace_id"`
	SpanID             string         `json:"span_id"`
	ParentSpanID       string         `json:"parent_span_id"`
	TraceState         string         `json:"trace_state"`
	SpanKind           string         `json:"span_kind"`
	SpanStatus         string         `json:"span_status"`
	Attributes         map[string]any `json:"attributes"`
	ResourceAttributes map[string]any `json:"resource_attributes"`
	ScopeAttributes    map[string]any `json:"scope_attributes"`
}

// Output represents the conformance test output file.
type Output struct {
	Results []Result `json:"results"`
}

// Result is the evaluation result for a single record.
type Result struct {
	RecordID         string   `json:"record_id"`
	Decision         string   `json:"decision"`
	MatchedPolicyIDs []string `json:"matched_policy_ids"`
}

func main() {
	policiesPath := flag.String("policies", "", "path to policies.json")
	inputPath := flag.String("input", "", "path to input.json")
	outputPath := flag.String("output", "", "path to output.json")
	flag.Parse()

	if *policiesPath == "" || *inputPath == "" || *outputPath == "" {
		fmt.Fprintf(os.Stderr, "usage: runner-go --policies <path> --input <path> --output <path>\n")
		os.Exit(1)
	}

	// Load policies
	registry := policy.NewPolicyRegistry()
	provider := policy.NewFileProvider(*policiesPath)
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

	var input Input
	if err := json.Unmarshal(inputData, &input); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse input: %v\n", err)
		os.Exit(1)
	}

	eng := policy.NewPolicyEngine(registry)

	var output Output

	switch input.SignalType {
	case "log":
		output, err = evaluateLogs(eng, registry, input.Records)
	case "metric":
		output, err = evaluateMetrics(eng, registry, input.Records)
	case "trace":
		output, err = evaluateTraces(eng, registry, input.Records)
	default:
		fmt.Fprintf(os.Stderr, "unknown signal type: %s\n", input.SignalType)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "evaluation error: %v\n", err)
		os.Exit(1)
	}

	// Write output
	outputData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal output: %v\n", err)
		os.Exit(1)
	}
	outputData = append(outputData, '\n')

	if err := os.WriteFile(*outputPath, outputData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write output: %v\n", err)
		os.Exit(1)
	}
}

func toBytes(s string) []byte {
	if s == "" {
		return nil
	}
	return []byte(s)
}

func evaluateLogs(eng *policy.PolicyEngine, registry *policy.PolicyRegistry, rawRecords json.RawMessage) (Output, error) {
	var records []LogRecord
	if err := json.Unmarshal(rawRecords, &records); err != nil {
		return Output{}, fmt.Errorf("failed to parse log records: %w", err)
	}

	var output Output
	for _, rec := range records {
		simple := &policy.SimpleLogRecord{
			Body:               toBytes(rec.Body),
			SeverityText:       toBytes(rec.SeverityText),
			TraceID:            toBytes(rec.TraceID),
			SpanID:             toBytes(rec.SpanID),
			LogAttributes:      rec.Attributes,
			ResourceAttributes: rec.ResourceAttributes,
			ScopeAttributes:    rec.ScopeAttributes,
		}

		// Reset stats before evaluation
		registry.CollectStats()

		result := policy.EvaluateLog(eng, simple, policy.SimpleLogMatcher)

		// Collect stats to find which policies matched
		matchedIDs := collectMatchedPolicies(registry)

		output.Results = append(output.Results, Result{
			RecordID:         rec.ID,
			Decision:         mapDecision(result),
			MatchedPolicyIDs: matchedIDs,
		})
	}

	return output, nil
}

func evaluateMetrics(eng *policy.PolicyEngine, registry *policy.PolicyRegistry, rawRecords json.RawMessage) (Output, error) {
	var records []MetricRecord
	if err := json.Unmarshal(rawRecords, &records); err != nil {
		return Output{}, fmt.Errorf("failed to parse metric records: %w", err)
	}

	var output Output
	for _, rec := range records {
		simple := &policy.SimpleMetricRecord{
			Name:                   toBytes(rec.Name),
			Description:            toBytes(rec.Description),
			Unit:                   toBytes(rec.Unit),
			Type:                   toBytes(rec.MetricType),
			AggregationTemporality: toBytes(rec.AggregationTemporality),
			DatapointAttributes:    rec.DatapointAttributes,
			ResourceAttributes:     rec.ResourceAttributes,
			ScopeAttributes:        rec.ScopeAttributes,
		}

		registry.CollectStats()

		result := policy.EvaluateMetric(eng, simple, policy.SimpleMetricMatcher)

		matchedIDs := collectMatchedPolicies(registry)

		output.Results = append(output.Results, Result{
			RecordID:         rec.ID,
			Decision:         mapDecision(result),
			MatchedPolicyIDs: matchedIDs,
		})
	}

	return output, nil
}

func evaluateTraces(eng *policy.PolicyEngine, registry *policy.PolicyRegistry, rawRecords json.RawMessage) (Output, error) {
	var records []TraceRecord
	if err := json.Unmarshal(rawRecords, &records); err != nil {
		return Output{}, fmt.Errorf("failed to parse trace records: %w", err)
	}

	var output Output
	for _, rec := range records {
		simple := &policy.SimpleSpanRecord{
			Name:               toBytes(rec.Name),
			TraceID:            toBytes(rec.TraceID),
			SpanID:             toBytes(rec.SpanID),
			ParentSpanID:       toBytes(rec.ParentSpanID),
			TraceState:         toBytes(rec.TraceState),
			Kind:               toBytes(rec.SpanKind),
			Status:             toBytes(rec.SpanStatus),
			SpanAttributes:     rec.Attributes,
			ResourceAttributes: rec.ResourceAttributes,
			ScopeAttributes:    rec.ScopeAttributes,
		}

		registry.CollectStats()

		result := policy.EvaluateTrace(eng, simple, policy.SimpleSpanMatcher)

		matchedIDs := collectMatchedPolicies(registry)

		output.Results = append(output.Results, Result{
			RecordID:         rec.ID,
			Decision:         mapDecision(result),
			MatchedPolicyIDs: matchedIDs,
		})
	}

	return output, nil
}

func mapDecision(result policy.EvaluateResult) string {
	switch result {
	case policy.ResultNoMatch:
		return "no_match"
	case policy.ResultKeep, policy.ResultKeepWithTransform:
		return "keep"
	case policy.ResultDrop:
		return "drop"
	case policy.ResultSample:
		return "sample"
	case policy.ResultRateLimit:
		return "rate_limit"
	default:
		return "unknown"
	}
}

func collectMatchedPolicies(registry *policy.PolicyRegistry) []string {
	stats := registry.CollectStats()
	var matched []string
	for _, s := range stats {
		if s.Hits > 0 {
			matched = append(matched, s.PolicyID)
		}
	}
	sort.Strings(matched)
	if matched == nil {
		matched = []string{}
	}
	return matched
}
