# policy-conformance

Conformance test suite for
[Policy spec](https://github.com/usetero/policy/blob/master/spec.md)
implementations. Verifies that policy evaluation engines in Go, Rust, and Zig
produce identical results when given the same policies and OpenTelemetry input
data.

## Repository structure

```
.
├── Taskfile.yml              # Test harness (build, test, bench, clean)
├── runners/
│   ├── go/                   # Go conformance runner (policy-go)
│   ├── rs/                   # Rust conformance runner (policy-rs)
│   └── zig/                  # Zig conformance runner (policy-zig)
├── server/                   # HTTP/gRPC conformance server (Go)
├── testcases/                # 184 test case directories
│   ├── logs_*/               # Log signal tests
│   ├── metrics_*/            # Metric signal tests
│   ├── traces_*/             # Trace signal tests
│   └── compound_*/           # Multi-signal / multi-batch tests
└── bin/                      # Hermit-managed toolchain
```

### Test case layout

Each test case is a directory under `testcases/` containing:

**Simple test** (single input/output):

```
testcases/logs_severity_drop/
├── policies.json             # Policy definitions
├── input.json                # OTLP JSON input
├── expected.json             # Expected OTLP JSON output
└── expected_stats.json       # Expected match statistics
```

The harness runs a simple test as follows:

1. Detect signal type from the directory name prefix (`logs_*` → log,
   `metrics_*` → metric, `traces_*` → trace)
2. Invoke the runner:
   ```
   ./runner-go --policies policies.json --input input.json \
               --output output_go.json --stats stats_go.json --signal log
   ```
3. Normalize both `expected.json` and `output_go.json` with jq (strip null
   fields, coerce numeric strings to numbers, sort keys)
4. Diff the normalized output against `expected.json` — any difference is a
   failure
5. Diff `stats_go.json` against `expected_stats.json` — any difference is a
   failure
6. Report PASS or FAIL (on failure, print the diff)

**Compound test** (multiple batches, stats checked once after all batches):

```
testcases/compound_mixed_signals/
├── policies.json             # Policy definitions (may span signals)
├── input_1.json              # Batch 1 (e.g., logs)
├── expected_1.json           # Expected output for batch 1
├── input_2.json              # Batch 2 (e.g., metrics)
├── expected_2.json           # Expected output for batch 2
├── input_3.json              # Batch 3 (e.g., traces)
├── expected_3.json           # Expected output for batch 3
└── expected_stats.json       # Merged stats across all batches
```

The harness runs a compound test as follows:

1. Iterate over `input_N.json` files sorted numerically
2. For each batch N:
   1. Detect signal type from the JSON content (`resourceLogs` → log,
      `resourceMetrics` → metric, `resourceSpans` → trace)
   2. Invoke the runner with `input_N.json`, writing `output_N_go.json` and
      `stats_N_go.json`
   3. Normalize and diff `output_N_go.json` against `expected_N.json`
3. After all batches, merge per-batch stats files with jq (sum `hits` and
   `misses` per `policy_id`)
4. Diff the merged stats against `expected_stats.json`
5. Report PASS or FAIL (on failure, print diffs for each failing batch and/or
   stats)

### Runners

All three runners implement the same CLI interface:

```
runner-{go,rs,zig} \
  --policies policies.json \
  --input input.json \
  --output output.json \
  --stats stats.json \
  --signal {log,metric,trace}
```

For HTTP/gRPC mode, `--policies` is replaced with `--server URL` or
`--grpc ADDR`.

| Runner       | Language | Policy engine | Protobuf codec              |
| ------------ | -------- | ------------- | --------------------------- |
| `runner-go`  | Go       | `policy-go`   | `protojson`                 |
| `runner-rs`  | Rust     | `policy-rs`   | `serde` + custom OTel types |
| `runner-zig` | Zig      | `policy-zig`  | Native proto JSON codec     |

## Prerequisites

- [Task](https://taskfile.dev/) (provided via `bin/`)
- Go 1.26+
- Rust (stable)
- Zig 0.15+
- [Hyperscan/Vectorscan](https://www.hyperscan.io/) (`task ci:setup` installs
  it)
- `jq` (provided via `bin/`)

## Running tests

### Build everything

```sh
task build       # Build all runners + conformance server
```

### File-based provider (CLI mode)

Runs each runner as a CLI process that reads policies from a local JSON file:

```sh
task test        # Run all 3 runners
task test:go     # Go only
task test:rs     # Rust only
task test:zig    # Zig only
```

### HTTP provider (server mode)

Runs the conformance server per test case, then uses the runner's `--server`
flag to fetch policies over HTTP:

```sh
task test:http       # All 3 runners via HTTP
task test:http:go    # Go only
task test:http:rs    # Rust only
task test:http:zig   # Zig only
```

**What happens for each http test case:**

1. Starts the conformance server on a random port:
   ```
   ./conformance-server --policies testcases/X/policies.json --http-port 0 --grpc-port 0
   ```
2. Reads `HTTP_PORT=N` and `GRPC_PORT=N` from stdout (via FIFO, no sleeps)
3. Invokes the runner:
   ```
   ./runner-go --server http://localhost:PORT/v1/policy/sync \
               --input testcases/X/input.json \
               --output testcases/X/output_go_http.json \
               --signal log
   ```
4. Fetches accumulated stats from `GET /stats`
5. Shuts down the server via `GET /shutdown`
6. Diffs output and stats (stats normalization strips `misses` and zero-hit
   policies since the server only reports `{policy_id, hits}` for matched
   policies)

### gRPC provider

Same as HTTP but uses `--grpc` flag:

```sh
task test:grpc       # Go + Rust via gRPC
task test:grpc:go
task test:grpc:rs
```

> Note: The Zig runner does not support gRPC.

### Other commands

```sh
task test:repeat TC=traces_sampling_50pct N=100 R=go   # Repeat one test N times
task bench                                              # Benchmark all runners with hyperfine
task clean                                              # Remove build artifacts and outputs
```

## Known issues

- `traces_event_attribute` and `traces_link_trace_id` are unimplemented across
  all runners

## Test case catalog

All 184 test cases listed below pass for all three runners (Go, Rust, Zig) in
both file-based and HTTP modes unless noted otherwise.

### Logs — matching

| Test case                                 | Description                                                    | Go                 | Zig                | Rust               |
| ----------------------------------------- | -------------------------------------------------------------- | ------------------ | ------------------ | ------------------ |
| `logs_all_dropped`                        | All log records match a drop policy; output is empty           | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_attribute_match`                    | Match log records by log attribute exact value                 | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_case_insensitive_ends_with`         | Case-insensitive `ends_with` matcher on severity               | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_case_insensitive_exact`             | Case-insensitive `exact` matcher on body                       | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_case_insensitive_regex`             | Case-insensitive regex matcher on body                         | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_case_insensitive_starts_with`       | Case-insensitive `starts_with` matcher on severity             | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_contains_ci`                        | Case-insensitive `contains` matcher on body                    | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_contains_cs`                        | Case-sensitive `contains` matcher on body                      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_empty_input`                        | Empty input (no log records) produces empty output             | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_empty_vs_missing_field`             | Distinguish between empty string and missing/null field        | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_enabled_false`                      | Disabled policy (`enabled: false`) is skipped entirely         | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_enabled_false_with_transforms`      | Disabled policy with transforms; transforms must not fire      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_ends_with`                          | `ends_with` matcher on severity text                           | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_event_name_field`                   | Match on the `event_name` log field                            | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_exact_drop`                         | Exact match on severity drops matching records                 | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_exists`                             | `exists: true` matcher on log attribute                        | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_exists_false`                       | `exists: false` matcher — match when attribute is absent       | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_keep_all_default`                   | Policy with `keep: "all"` passes all matched records through   | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_multiple_matchers`                  | Policy with multiple matchers (AND logic)                      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_multiple_policies_most_restrictive` | Most-restrictive keep wins when multiple policies match        | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_multiple_resources`                 | Multiple resources in input processed independently            | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_negated_match`                      | `negate: true` inverts a matcher                               | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_nested_attribute`                   | Match on nested attribute path (e.g., `["http", "method"]`)    | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_nested_attribute_deep`              | Match on deeply nested attribute path (3+ levels)              | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_no_match`                           | No policy matches; all records pass through unmodified         | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_overlapping_policies`               | Multiple policies match the same record                        | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_policy_ordering_determinism`        | Policies evaluated in deterministic (alphanumeric by ID) order | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_regex_drop`                         | Regex matcher drops matching records                           | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_resource_attr`                      | Match on resource attribute                                    | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_resource_schema_url`                | Match on resource schema URL                                   | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_scope_attr`                         | Match on scope attribute                                       | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_scope_schema_url`                   | Match on scope schema URL                                      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_severity_drop`                      | Drop by severity text exact match                              | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_span_id_field`                      | Match on the `span_id` log field                               | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_starts_with`                        | `starts_with` matcher on severity text                         | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_three_matchers`                     | Three matchers combined in a single policy (AND)               | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_trace_id_field`                     | Match on the `trace_id` log field                              | :white_check_mark: | :white_check_mark: | :white_check_mark: |

### Logs — sampling and rate limiting

| Test case                       | Description                                            | Go                 | Zig                | Rust               |
| ------------------------------- | ------------------------------------------------------ | ------------------ | ------------------ | ------------------ |
| `logs_rate_limit`               | Rate limit to N records per second                     | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_rate_limit_drop_overlap`  | `keep: "none"` overrides rate limit on the same record | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_rate_limit_per_minute`    | Rate limit specified as N per minute                   | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_sample_key_attribute`     | Sampling keyed by log attribute value                  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_sample_key_resource_attr` | Sampling keyed by resource attribute value             | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_sample_key_scope_attr`    | Sampling keyed by scope attribute value                | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_sampling_10pct`           | 10% sampling rate                                      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_sampling_25pct`           | 25% sampling rate                                      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_sampling_50pct`           | 50% sampling rate                                      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_sampling_75pct`           | 75% sampling rate                                      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_sampling_drop_overlap`    | `keep: "none"` overrides sampling on the same record   | :white_check_mark: | :white_check_mark: | :white_check_mark: |

### Logs — transforms

| Test case                                    | Description                                                      | Go                 | Zig                | Rust               |
| -------------------------------------------- | ---------------------------------------------------------------- | ------------------ | ------------------ | ------------------ |
| `logs_transform_add_attr_upsert_absent`      | Add attribute with `upsert: true` when field absent (insert)     | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_add_attribute`               | Add a new log attribute                                          | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_add_body`                    | Add body to log record when body is null                         | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_add_body_no_upsert_exists`   | Add body without upsert when body exists (no-op)                 | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_add_body_upsert_exists`      | Add body with `upsert: true` when body exists (overwrite)        | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_add_no_upsert`               | Add attribute with `upsert: false` when field exists (no-op)     | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_add_no_upsert_new_field`     | Add attribute with `upsert: false` when field absent (insert)    | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_add_resource_attr`           | Add a new resource attribute                                     | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_add_scope_attr`              | Add a new scope attribute                                        | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_add_upsert`                  | Add attribute with `upsert: true` overwrites existing value      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_drop_skips_transform`        | Transforms are not applied to records dropped by `keep: "none"`  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_execution_order`             | Transforms execute in spec order: remove → redact → rename → add | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_multiple_policies`           | Multiple policies each apply their own transforms                | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_multiple_same_field`         | Multiple transforms targeting the same field in one policy       | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_redact_attribute`            | Redact a log attribute value with `[REDACTED]`                   | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_redact_body`                 | Redact the log body field                                        | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_redact_nonexistent`          | Redact a non-existent field (no-op)                              | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_redact_resource_attr`        | Redact a resource attribute                                      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_redact_scope_attr`           | Redact a scope attribute                                         | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_remove_attribute`            | Remove a log attribute                                           | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_remove_body`                 | Remove the log body field                                        | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_remove_nonexistent`          | Remove a non-existent field (no-op)                              | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_remove_resource_attr`        | Remove a resource attribute                                      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_remove_scope_attr`           | Remove a scope attribute                                         | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_rename_attribute`            | Rename a log attribute                                           | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_rename_no_upsert`            | Rename with `upsert: false` when target exists (no-op)           | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_rename_nonexistent`          | Rename a non-existent source attribute (no-op)                   | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_rename_resource_attr`        | Rename a resource attribute                                      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_rename_scope_attr`           | Rename a scope attribute                                         | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_rename_source_absent`        | Rename when source attribute absent, `upsert: false` (no-op)     | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_rename_target_absent`        | Rename when target absent, `upsert: false` (normal rename)       | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_rename_upsert`               | Rename with `upsert: true` overwrites existing target            | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_rename_upsert_source_absent` | Rename with `upsert: true` when source absent (no-op)            | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_rename_upsert_target_absent` | Rename with `upsert: true` when target absent (rename)           | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_with_rate_limit`             | Transforms applied to records that survive rate limiting         | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `logs_transform_with_sampling`               | Transforms applied to records that survive sampling              | :white_check_mark: | :white_check_mark: | :white_check_mark: |

### Metrics

| Test case                            | Description                                         | Go                 | Zig                | Rust               |
| ------------------------------------ | --------------------------------------------------- | ------------------ | ------------------ | ------------------ |
| `metrics_aggregation_temporality`    | Match by aggregation temporality (delta/cumulative) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_case_insensitive`           | Case-insensitive metric name matching               | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_cumulative_temporality`     | Match cumulative temporality specifically           | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_description`                | Match by metric description field                   | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_drop_by_attr`               | Drop metrics by datapoint attribute                 | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_drop_by_name`               | Drop metrics by name exact match                    | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_empty_input`                | Empty input (no metrics) produces empty output      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_ends_with`                  | `ends_with` matcher on metric name                  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_exists`                     | `exists: true` matcher on datapoint attribute       | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_exists_false`               | `exists: false` matcher on datapoint attribute      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_exponential_histogram_type` | Match exponential histogram metric type             | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_histogram_type`             | Match histogram metric type                         | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_keep`                       | Basic keep policy for metrics                       | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_multiple_matchers`          | Multiple matchers combined (AND logic) for metrics  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_multiple_policies`          | Multiple metric policies evaluated together         | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_multiple_resources`         | Multiple resources in metric input                  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_negate`                     | Negated matcher for metrics                         | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_negate_temporality`         | Negated temporality matcher                         | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_negate_type`                | Negated metric type matcher                         | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_overlapping_miss`           | Overlapping policies where one misses               | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_resource_attr`              | Match on resource attribute for metrics             | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_resource_schema_url`        | Match on resource schema URL for metrics            | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_scope_attr`                 | Match on scope attribute for metrics                | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_scope_name`                 | Match on scope name for metrics                     | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_scope_schema_url`           | Match on scope schema URL for metrics               | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_scope_version`              | Match on scope version for metrics                  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_starts_with`                | `starts_with` matcher on metric name                | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_sum_type`                   | Match sum metric type                               | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_summary_type`               | Match summary metric type                           | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_three_policies`             | Three metric policies evaluated together            | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_type_filter`                | Filter metrics by type (gauge/sum/histogram)        | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `metrics_unit`                       | Match by metric unit field                          | :white_check_mark: | :white_check_mark: | :white_check_mark: |

### Traces — matching

| Test case                        | Description                                     | Go                 | Zig                | Rust               |
| -------------------------------- | ----------------------------------------------- | ------------------ | ------------------ | ------------------ |
| `traces_case_insensitive`        | Case-insensitive span name matching             | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_drop_0pct`               | Drop at 0% (all sampled out)                    | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_empty_input`             | Empty input (no spans) produces empty output    | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_error_vs_health`         | Distinguish error spans from health check spans | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_event_name`              | Match on span event name                        | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_exists`                  | `exists: true` matcher on span attribute        | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_exists_false`            | `exists: false` matcher on span attribute       | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_multiple_matchers`       | Multiple matchers combined (AND) for traces     | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_multiple_resources`      | Multiple resources in trace input               | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_name_contains`           | `contains` matcher on span name                 | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_name_ends_with`          | `ends_with` matcher on span name                | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_name_regex`              | Regex matcher on span name                      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_name_starts_with`        | `starts_with` matcher on span name              | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_negate`                  | Negated matcher for traces                      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_negate_span_kind`        | Negated span kind matcher                       | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_negate_span_status`      | Negated span status matcher                     | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_overlapping`             | Overlapping trace policies on the same spans    | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_parent_span_id`          | Match on parent span ID field                   | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_resource_attr`           | Match on resource attribute for traces          | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_scope_attr`              | Match on scope attribute for traces             | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_scope_name`              | Match on scope name for traces                  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_scope_schema_url`        | Match on scope schema URL for traces            | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_scope_version`           | Match on scope version for traces               | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_span_attribute`          | Match on span attribute exact value             | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_span_attribute_contains` | `contains` matcher on span attribute            | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_span_kind`               | Match on span kind (server)                     | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_span_kind_client`        | Match on span kind (client)                     | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_span_kind_consumer`      | Match on span kind (consumer)                   | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_span_kind_producer`      | Match on span kind (producer)                   | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_span_status_error`       | Match on span status = error                    | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_span_status_ok`          | Match on span status = ok                       | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_span_status_unset`       | Match on span status = unset                    | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_trace_state`             | Match on trace state field                      | :white_check_mark: | :white_check_mark: | :white_check_mark: |

### Traces — sampling

| Test case                      | Description                                             | Go                 | Zig                | Rust               |
| ------------------------------ | ------------------------------------------------------- | ------------------ | ------------------ | ------------------ |
| `traces_keep_100pct`           | Keep at 100% (all sampled in, writes `th:0` tracestate) | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_sampling_10pct`        | 10% trace sampling with deterministic hash              | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_sampling_25pct`        | 25% trace sampling                                      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_sampling_50pct`        | 50% trace sampling                                      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_sampling_75pct`        | 75% trace sampling                                      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_sampling_equalizing`   | Equalizing sampling algorithm                           | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_sampling_fail_closed`  | `fail_closed: true` drops spans without valid trace ID  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_sampling_precision`    | High-precision sampling threshold encoding              | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_sampling_proportional` | Proportional sampling algorithm                         | :white_check_mark: | :white_check_mark: | :white_check_mark: |

### Traces — tracestate

| Test case                                    | Description                                               | Go                 | Zig                | Rust               |
| -------------------------------------------- | --------------------------------------------------------- | ------------------ | ------------------ | ------------------ |
| `traces_tracestate_equalizing_incoming_th`   | Equalizing sampler with pre-existing `th` in tracestate   | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_tracestate_fail_closed_true`         | Fail-closed behavior with tracestate present              | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_tracestate_mixed`                    | Mixed tracestate scenarios (some with, some without)      | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_tracestate_overwrite_ot`             | Overwrite existing `ot` vendor key in tracestate          | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_tracestate_preserve_vendors`         | Preserve non-`ot` vendor keys in tracestate               | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_tracestate_proportional_incoming_th` | Proportional sampler with pre-existing `th` in tracestate | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_tracestate_rv_consistency_check`     | Randomness value consistency check in tracestate          | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_tracestate_rv_randomness`            | Random value (`rv`) written to tracestate                 | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `traces_tracestate_write_basic`              | Basic tracestate write with sampling threshold            | :white_check_mark: | :white_check_mark: | :white_check_mark: |

### Compound tests

| Test case                                  | Description                                                                      | Go                 | Zig                | Rust               |
| ------------------------------------------ | -------------------------------------------------------------------------------- | ------------------ | ------------------ | ------------------ |
| `compound_all_keep_types`                  | All keep types (all/none/sample/rate_limit) in one policy set                    | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `compound_conflicting_keeps`               | Conflicting keep decisions across policies; most restrictive wins                | :white_check_mark: | :white_check_mark: | :x: ENG-228        |
| `compound_datapoint_attr_types`            | Datapoint attribute matching across histogram, summary, gauge                    | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `compound_disabled_mixed`                  | Mix of enabled and disabled policies; disabled transforms must not fire          | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `compound_double_negation`                 | `exists: false` + `negate: true` semantics                                       | :x: ENG-229        | :white_check_mark: | :white_check_mark: |
| `compound_empty_vs_missing`                | Empty string vs null/absent field behavior across signals                        | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `compound_many_policies_fanout`            | 50+ policies each targeting a different service; verifies no cross-contamination | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `compound_mixed_signals`                   | Policies spanning logs, metrics, and traces in one set                           | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `compound_negation_overlap`                | Policies with negated matchers creating complex intersections                    | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `compound_nested_attributes`               | Nested attribute paths across all signal types                                   | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `compound_rate_limit_most_restrictive`     | `keep: "none"` overrides rate limit; confirms none > rate_limit                  | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `compound_regex_edge_cases`                | Character classes, anchoring, alternation, UUID patterns, escaped brackets       | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `compound_sampling_interactions`           | Trace sampling with fail_closed, 0% drop overriding sampling                     | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `compound_scope_isolation`                 | Resource/scope attribute transforms are isolated per scope                       | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `compound_transform_chain`                 | Cross-policy transform visibility (transforms applied after all matching)        | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `compound_transform_ordering_alphanumeric` | Policies evaluated in alphanumeric ID order, not array order                     | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| `compound_transforms_across_policies`      | Multiple policies with add/redact/rename transforms on same records              | :white_check_mark: | :white_check_mark: | :white_check_mark: |

### Summary

| Signal    | Tests   | Go      | Zig     | Rust    |
| --------- | ------- | ------- | ------- | ------- |
| Logs      | 84      | 84      | 84      | 84      |
| Metrics   | 32      | 32      | 32      | 32      |
| Traces    | 51      | 51      | 51      | 51      |
| Compound  | 17      | 16      | 17      | 16      |
| **Total** | **184** | **183** | **184** | **183** |
