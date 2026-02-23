# Missing Conformance Tests

## Traces (blocked — all runners unimplemented)

- [ ] `traces_event_attribute` — match on span event attributes (all runners return nil for `event_attribute`)
- [ ] `traces_link_trace_id` — match spans by linked trace ID (all runners return nil for `link_trace_id`)

## Compound tests

### Keep type interactions
- [x] `compound_all_keep_types` — all/none/sample/rate_limit(N/s)/rate_limit(N/m) under one policy set
- [x] `compound_rate_limit_most_restrictive` — rate_limit vs none precedence; confirms none > rate_limit

### Sampling
- [x] `compound_sampling_interactions` — trace sampling with fail_closed contrast, drop (0%) overriding sampling, mixed fail_closed=true/false with missing trace_id

### Matching edge cases
- [x] `compound_regex_edge_cases` — character classes, anchoring, alternation, UUID patterns, escaped brackets, case-insensitive regex
- [x] `compound_double_negation` — `exists: false` + `negate: true` (FAILS Go — ENG-229)
- [x] `compound_empty_vs_missing` — empty string vs null/absent field behavior
- [x] `compound_nested_attributes` — nested attribute paths across all signal types

### Transform edge cases
- [x] `compound_transform_chain` — cross-policy transform visibility (confirmed: transforms applied after all matching)
- [x] `compound_scope_isolation` — resource/scope attribute transform isolation

### Metric-specific
- [x] `compound_datapoint_attr_types` — datapoint attribute matching across histogram, summary, gauge

## Known issues

- ~~`traces_sampling_hash_seed`~~ — removed; non-zero hash_seed produces different FNV inputs across runners
- ~~`*_no_matchers`~~ — removed; `match: []` is not a valid policy
- ENG-228: Rust evaluates policies in array order instead of alphanumeric (fails `compound_conflicting_keeps`)
- ENG-229: Go ignores `negate` flag on existence checks — `exists: false, negate: true` should mean "field exists" but Go treats it as "field absent" (fails `compound_double_negation`)
