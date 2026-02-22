# Missing Conformance Tests

## Traces

- [x] `traces_span_status_error` — drop spans with ERROR status (standalone)
- [x] `traces_parent_span_id` — match on `parent_span_id` field
- [x] `traces_trace_state` — match on `trace_state` field
- [x] `traces_negate_span_kind` — negated span_kind matcher
- [x] `traces_negate_span_status` — negated span_status matcher
- [x] `traces_scope_version` — match on `scope_version` field
- [x] `traces_scope_schema_url` — match on `scope_schema_url` field
- [x] `traces_multiple_resources` — multiple resources/scopes in input
- [ ] `traces_event_attribute` — match on span event attributes (Go only; Rust/Zig not evaluated)
- [ ] `traces_link_trace_id` — match spans by linked trace ID (Go only; Rust/Zig not evaluated)
- [x] `traces_sampling_proportional` — proportional sampling mode
- [x] `traces_sampling_equalizing` — equalizing sampling mode
- [x] `traces_sampling_precision` — custom `sampling_precision` parameter
- ~~`traces_sampling_hash_seed`~~ — removed; non-zero hash_seed produces different FNV inputs across runners (raw bytes vs hex vs base64)
- [x] `traces_sampling_fail_closed` — `fail_closed: false` keeps spans without trace ID

## Metrics

- [x] `metrics_scope_name` — match on `scope_name` field
- [x] `metrics_scope_version` — match on `scope_version` field
- [x] `metrics_scope_schema_url` — match on `scope_schema_url` field
- [x] `metrics_sum_type` — drop sum metrics
- [x] `metrics_cumulative_temporality` — filter by cumulative aggregation temporality
- [x] `metrics_negate_type` — negated metric_type matcher
- [x] `metrics_negate_temporality` — negated aggregation_temporality matcher
- [x] `metrics_multiple_resources` — multiple resources/scopes in input

## Logs

- [x] `logs_scope_schema_url` — match on `scope_schema_url` field
- [x] `logs_nested_attribute_deep` — 3+ level nested attribute path
- [x] `logs_sample_key_resource_attr` — sample_key targeting resource_attribute
- [x] `logs_sample_key_scope_attr` — sample_key targeting scope_attribute
- [x] `logs_transform_rename_resource_attr` — rename a resource attribute
- [x] `logs_transform_rename_scope_attr` — rename a scope attribute
- [x] `logs_transform_add_resource_attr` — add a resource attribute
- [x] `logs_transform_add_scope_attr` — add a scope attribute
- [x] `logs_transform_redact_resource_attr` — redact a resource attribute
- [x] `logs_transform_redact_scope_attr` — redact a scope attribute
- [x] `logs_transform_add_body` — add/set body field via transform
- [x] `logs_enabled_false_with_transforms` — disabled policy skips transforms

## Cross-cutting

- [x] `logs_empty_input` — zero records in input
- [x] `metrics_empty_input` — zero records in input
- [x] `traces_empty_input` — zero records in input
- ~~`*_no_matchers`~~ — removed; `match: []` is not a valid policy
