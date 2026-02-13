use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::process;

use clap::Parser;
use policy_rs::proto::tero::policy::v1::{LogField, MetricField, TraceField};
use policy_rs::{
    FileProvider, LogFieldSelector, LogSignal, Matchable, MetricFieldSelector, MetricSignal,
    PolicyEngine, PolicyRegistry, TraceFieldSelector, TraceSignal, Transformable,
};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    policies: String,
    #[arg(long)]
    input: String,
    #[arg(long)]
    output: String,
}

#[derive(Deserialize)]
struct Input {
    signal_type: String,
    records: serde_json::Value,
}

#[derive(Deserialize)]
struct LogRecord {
    id: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    severity_text: String,
    #[serde(default)]
    trace_id: String,
    #[serde(default)]
    span_id: String,
    #[serde(default)]
    attributes: HashMap<String, String>,
    #[serde(default)]
    resource_attributes: HashMap<String, String>,
    #[serde(default)]
    scope_attributes: HashMap<String, String>,
}

#[derive(Deserialize)]
struct MetricRecord {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    unit: String,
    #[serde(default)]
    metric_type: String,
    #[serde(default)]
    aggregation_temporality: String,
    #[serde(default)]
    datapoint_attributes: HashMap<String, String>,
    #[serde(default)]
    resource_attributes: HashMap<String, String>,
    #[serde(default)]
    scope_attributes: HashMap<String, String>,
}

#[derive(Deserialize)]
struct TraceRecord {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    trace_id: String,
    #[serde(default)]
    span_id: String,
    #[serde(default)]
    parent_span_id: String,
    #[serde(default)]
    trace_state: String,
    #[serde(default)]
    span_kind: String,
    #[serde(default)]
    span_status: String,
    #[serde(default)]
    attributes: HashMap<String, String>,
    #[serde(default)]
    resource_attributes: HashMap<String, String>,
    #[serde(default)]
    scope_attributes: HashMap<String, String>,
}

#[derive(Serialize)]
struct Output {
    results: Vec<ResultEntry>,
}

#[derive(Serialize)]
struct ResultEntry {
    record_id: String,
    decision: String,
    matched_policy_ids: Vec<String>,
}

// --- Matchable implementations ---

impl Matchable for LogRecord {
    type Signal = LogSignal;

    fn get_field(&self, field: &LogFieldSelector) -> Option<Cow<'_, str>> {
        match field {
            LogFieldSelector::Simple(f) => match f {
                LogField::Body => non_empty(&self.body),
                LogField::SeverityText => non_empty(&self.severity_text),
                LogField::TraceId => non_empty(&self.trace_id),
                LogField::SpanId => non_empty(&self.span_id),
                _ => None,
            },
            LogFieldSelector::LogAttribute(path) => path
                .first()
                .and_then(|k| self.attributes.get(k))
                .map(|s| Cow::Borrowed(s.as_str())),
            LogFieldSelector::ResourceAttribute(path) => path
                .first()
                .and_then(|k| self.resource_attributes.get(k))
                .map(|s| Cow::Borrowed(s.as_str())),
            LogFieldSelector::ScopeAttribute(path) => path
                .first()
                .and_then(|k| self.scope_attributes.get(k))
                .map(|s| Cow::Borrowed(s.as_str())),
        }
    }
}

impl Matchable for MetricRecord {
    type Signal = MetricSignal;

    fn get_field(&self, field: &MetricFieldSelector) -> Option<Cow<'_, str>> {
        match field {
            MetricFieldSelector::Simple(f) => match f {
                MetricField::Name => non_empty(&self.name),
                MetricField::Description => non_empty(&self.description),
                MetricField::Unit => non_empty(&self.unit),
                _ => None,
            },
            MetricFieldSelector::DatapointAttribute(path) => path
                .first()
                .and_then(|k| self.datapoint_attributes.get(k))
                .map(|s| Cow::Borrowed(s.as_str())),
            MetricFieldSelector::ResourceAttribute(path) => path
                .first()
                .and_then(|k| self.resource_attributes.get(k))
                .map(|s| Cow::Borrowed(s.as_str())),
            MetricFieldSelector::ScopeAttribute(path) => path
                .first()
                .and_then(|k| self.scope_attributes.get(k))
                .map(|s| Cow::Borrowed(s.as_str())),
            MetricFieldSelector::Type => non_empty(&self.metric_type),
            MetricFieldSelector::Temporality => non_empty(&self.aggregation_temporality),
        }
    }
}

impl Matchable for TraceRecord {
    type Signal = TraceSignal;

    fn get_field(&self, field: &TraceFieldSelector) -> Option<Cow<'_, str>> {
        match field {
            TraceFieldSelector::Simple(f) => match f {
                TraceField::Name => non_empty(&self.name),
                TraceField::TraceId => non_empty(&self.trace_id),
                TraceField::SpanId => non_empty(&self.span_id),
                TraceField::ParentSpanId => non_empty(&self.parent_span_id),
                TraceField::TraceState => non_empty(&self.trace_state),
                _ => None,
            },
            TraceFieldSelector::SpanAttribute(path) => path
                .first()
                .and_then(|k| self.attributes.get(k))
                .map(|s| Cow::Borrowed(s.as_str())),
            TraceFieldSelector::ResourceAttribute(path) => path
                .first()
                .and_then(|k| self.resource_attributes.get(k))
                .map(|s| Cow::Borrowed(s.as_str())),
            TraceFieldSelector::ScopeAttribute(path) => path
                .first()
                .and_then(|k| self.scope_attributes.get(k))
                .map(|s| Cow::Borrowed(s.as_str())),
            TraceFieldSelector::SpanKind => non_empty(&self.span_kind),
            TraceFieldSelector::SpanStatus => non_empty(&self.span_status),
            TraceFieldSelector::EventName => None,
            TraceFieldSelector::EventAttribute(_) => None,
            TraceFieldSelector::LinkTraceId => None,
            TraceFieldSelector::SamplingThreshold => None,
        }
    }
}

impl Transformable for TraceRecord {
    fn remove_field(&mut self, _field: &TraceFieldSelector) -> bool {
        false
    }

    fn redact_field(&mut self, _field: &TraceFieldSelector, _replacement: &str) -> bool {
        false
    }

    fn rename_field(&mut self, _from: &TraceFieldSelector, _to: &str, _upsert: bool) -> bool {
        false
    }

    fn add_field(&mut self, field: &TraceFieldSelector, value: &str, _upsert: bool) -> bool {
        if matches!(field, TraceFieldSelector::SamplingThreshold) {
            self.trace_state = if self.trace_state.is_empty() {
                format!("ot=th:{value}")
            } else {
                format!("{},ot=th:{value}", self.trace_state)
            };
            return true;
        }
        false
    }
}

fn non_empty(s: &str) -> Option<Cow<'_, str>> {
    if s.is_empty() {
        None
    } else {
        Some(Cow::Borrowed(s))
    }
}

fn map_decision(result: &policy_rs::EvaluateResult) -> &'static str {
    match result {
        policy_rs::EvaluateResult::NoMatch => "no_match",
        policy_rs::EvaluateResult::Keep { .. } => "keep",
        policy_rs::EvaluateResult::Drop { .. } => "drop",
        policy_rs::EvaluateResult::Sample { keep, .. } => {
            if *keep {
                "keep"
            } else {
                "drop"
            }
        }
        policy_rs::EvaluateResult::RateLimit { allowed, .. } => {
            if *allowed {
                "keep"
            } else {
                "drop"
            }
        }
    }
}

fn matched_policy_id(result: &policy_rs::EvaluateResult) -> Vec<String> {
    match result {
        policy_rs::EvaluateResult::NoMatch => vec![],
        policy_rs::EvaluateResult::Keep { policy_id, .. }
        | policy_rs::EvaluateResult::Drop { policy_id, .. }
        | policy_rs::EvaluateResult::Sample { policy_id, .. }
        | policy_rs::EvaluateResult::RateLimit { policy_id, .. } => vec![policy_id.clone()],
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();

    // Load policies
    let registry = PolicyRegistry::new();
    let provider = FileProvider::new(&args.policies);
    if let Err(e) = registry.subscribe(&provider) {
        eprintln!("failed to load policies: {e}");
        process::exit(1);
    }
    let snapshot = registry.snapshot();

    // Read input
    let input_data = fs::read_to_string(&args.input).unwrap_or_else(|e| {
        eprintln!("failed to read input: {e}");
        process::exit(1);
    });
    let input: Input = serde_json::from_str(&input_data).unwrap_or_else(|e| {
        eprintln!("failed to parse input: {e}");
        process::exit(1);
    });

    let engine = PolicyEngine::new();

    let output = match input.signal_type.as_str() {
        "log" => {
            let records: Vec<LogRecord> =
                serde_json::from_value(input.records).unwrap_or_else(|e| {
                    eprintln!("failed to parse log records: {e}");
                    process::exit(1);
                });
            evaluate_logs(&engine, &snapshot, records).await
        }
        "metric" => {
            let records: Vec<MetricRecord> =
                serde_json::from_value(input.records).unwrap_or_else(|e| {
                    eprintln!("failed to parse metric records: {e}");
                    process::exit(1);
                });
            evaluate_metrics(&engine, &snapshot, records).await
        }
        "trace" => {
            let records: Vec<TraceRecord> =
                serde_json::from_value(input.records).unwrap_or_else(|e| {
                    eprintln!("failed to parse trace records: {e}");
                    process::exit(1);
                });
            evaluate_traces(&engine, &snapshot, records).await
        }
        other => {
            eprintln!("unknown signal type: {other}");
            process::exit(1);
        }
    };

    // Write output
    let output_data = serde_json::to_string_pretty(&output).unwrap_or_else(|e| {
        eprintln!("failed to serialize output: {e}");
        process::exit(1);
    });
    fs::write(&args.output, format!("{output_data}\n")).unwrap_or_else(|e| {
        eprintln!("failed to write output: {e}");
        process::exit(1);
    });
}

async fn evaluate_logs(
    engine: &PolicyEngine,
    snapshot: &policy_rs::registry::PolicySnapshot,
    records: Vec<LogRecord>,
) -> Output {
    let mut results = Vec::new();
    for rec in &records {
        let result = engine.evaluate(snapshot, rec).await.unwrap_or_else(|e| {
            eprintln!("evaluation error: {e}");
            process::exit(1);
        });
        results.push(ResultEntry {
            record_id: rec.id.clone(),
            decision: map_decision(&result).to_string(),
            matched_policy_ids: matched_policy_id(&result),
        });
    }
    Output { results }
}

async fn evaluate_metrics(
    engine: &PolicyEngine,
    snapshot: &policy_rs::registry::PolicySnapshot,
    records: Vec<MetricRecord>,
) -> Output {
    let mut results = Vec::new();
    for rec in &records {
        let result = engine.evaluate(snapshot, rec).await.unwrap_or_else(|e| {
            eprintln!("evaluation error: {e}");
            process::exit(1);
        });
        results.push(ResultEntry {
            record_id: rec.id.clone(),
            decision: map_decision(&result).to_string(),
            matched_policy_ids: matched_policy_id(&result),
        });
    }
    Output { results }
}

async fn evaluate_traces(
    engine: &PolicyEngine,
    snapshot: &policy_rs::registry::PolicySnapshot,
    mut records: Vec<TraceRecord>,
) -> Output {
    let mut results = Vec::new();
    for rec in &mut records {
        let id = rec.id.clone();
        let result = engine
            .evaluate_trace(snapshot, rec)
            .await
            .unwrap_or_else(|e| {
                eprintln!("evaluation error: {e}");
                process::exit(1);
            });
        results.push(ResultEntry {
            record_id: id,
            decision: map_decision(&result).to_string(),
            matched_policy_ids: matched_policy_id(&result),
        });
    }
    Output { results }
}
