use std::fs;
use std::process;

use clap::Parser;
use policy_rs::{FileProvider, PolicyEngine, PolicyRegistry};
use serde::{Deserialize, Serialize};

mod eval;
mod otel;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    policies: String,
    #[arg(long)]
    input: String,
    #[arg(long)]
    output: String,
    #[arg(long)]
    stats: String,
    #[arg(long)]
    signal: String,
}

#[derive(Serialize, Deserialize)]
struct StatsOutput {
    policies: Vec<PolicyHit>,
}

#[derive(Serialize, Deserialize)]
struct PolicyHit {
    policy_id: String,
    hits: u64,
}

// ─── Stats ───────────────────────────────────────────────────────────

fn write_stats(path: &str, registry: &PolicyRegistry) {
    let snapshot = registry.snapshot();
    let mut policies = Vec::new();
    for entry in snapshot.iter() {
        let stats = entry.stats.reset_all();
        if stats.match_hits > 0 {
            policies.push(PolicyHit {
                policy_id: entry.policy.id().to_string(),
                hits: stats.match_hits,
            });
        }
    }
    let output = StatsOutput { policies };
    let data = serde_json::to_string(&output).unwrap_or_else(|e| {
        eprintln!("failed to serialize stats: {e}");
        process::exit(1);
    });
    fs::write(path, data).unwrap_or_else(|e| {
        eprintln!("failed to write stats: {e}");
        process::exit(1);
    });
}

// ─── Signal processing ──────────────────────────────────────────────

async fn process_logs(
    engine: &PolicyEngine,
    snapshot: &policy_rs::PolicySnapshot,
    input_data: &[u8],
) -> Vec<u8> {
    let mut data: otel::LogsData = serde_json::from_slice(input_data).unwrap_or_else(|e| {
        eprintln!("failed to parse logs: {e}");
        process::exit(1);
    });

    for rl in &mut data.resource_logs {
        for sl in &mut rl.scope_logs {
            let mut kept = Vec::new();
            for rec in &sl.log_records {
                let ctx = eval::LogContext {
                    record: rec,
                    resource: rl.resource.as_ref(),
                    scope: sl.scope.as_ref(),
                };
                let result = engine.evaluate(snapshot, &ctx).await.unwrap_or_else(|e| {
                    eprintln!("evaluation error: {e}");
                    process::exit(1);
                });
                if !matches!(result, policy_rs::EvaluateResult::Drop { .. }) {
                    kept.push(rec.clone());
                }
            }
            sl.log_records = kept;
        }
        rl.scope_logs.retain(|sl| !sl.log_records.is_empty());
    }
    data.resource_logs.retain(|rl| !rl.scope_logs.is_empty());

    serde_json::to_vec(&data).unwrap_or_else(|e| {
        eprintln!("failed to serialize logs: {e}");
        process::exit(1);
    })
}

async fn process_metrics(
    engine: &PolicyEngine,
    snapshot: &policy_rs::PolicySnapshot,
    input_data: &[u8],
) -> Vec<u8> {
    let mut data: otel::MetricsData = serde_json::from_slice(input_data).unwrap_or_else(|e| {
        eprintln!("failed to parse metrics: {e}");
        process::exit(1);
    });

    for rm in &mut data.resource_metrics {
        for sm in &mut rm.scope_metrics {
            let mut kept = Vec::new();
            for m in &sm.metrics {
                let dp_attrs = m
                    .data
                    .as_ref()
                    .map(|d| d.first_datapoint_attributes())
                    .unwrap_or(&[]);
                let ctx = eval::MetricContext {
                    metric: m,
                    datapoint_attributes: dp_attrs,
                    resource: rm.resource.as_ref(),
                    scope: sm.scope.as_ref(),
                };
                let result = engine.evaluate(snapshot, &ctx).await.unwrap_or_else(|e| {
                    eprintln!("evaluation error: {e}");
                    process::exit(1);
                });
                if !matches!(result, policy_rs::EvaluateResult::Drop { .. }) {
                    kept.push(m.clone());
                }
            }
            sm.metrics = kept;
        }
        rm.scope_metrics.retain(|sm| !sm.metrics.is_empty());
    }
    data.resource_metrics
        .retain(|rm| !rm.scope_metrics.is_empty());

    serde_json::to_vec(&data).unwrap_or_else(|e| {
        eprintln!("failed to serialize metrics: {e}");
        process::exit(1);
    })
}

async fn process_traces(
    engine: &PolicyEngine,
    snapshot: &policy_rs::PolicySnapshot,
    input_data: &[u8],
) -> Vec<u8> {
    let mut data: otel::TracesData = serde_json::from_slice(input_data).unwrap_or_else(|e| {
        eprintln!("failed to parse traces: {e}");
        process::exit(1);
    });

    for rs in &mut data.resource_spans {
        for ss in &mut rs.scope_spans {
            let mut kept = Vec::new();
            for span in &ss.spans {
                let ctx = eval::TraceContext {
                    span: span,
                    resource: rs.resource.as_ref(),
                    scope: ss.scope.as_ref(),
                };
                let result = engine.evaluate(snapshot, &ctx).await.unwrap_or_else(|e| {
                    eprintln!("evaluation error: {e}");
                    process::exit(1);
                });
                if !matches!(result, policy_rs::EvaluateResult::Drop { .. }) {
                    kept.push(span.clone());
                }
            }
            ss.spans = kept;
        }
        rs.scope_spans.retain(|ss| !ss.spans.is_empty());
    }
    data.resource_spans.retain(|rs| !rs.scope_spans.is_empty());

    serde_json::to_vec(&data).unwrap_or_else(|e| {
        eprintln!("failed to serialize traces: {e}");
        process::exit(1);
    })
}

// ─── Main ────────────────────────────────────────────────────────────

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

    // Reset stats
    for entry in snapshot.iter() {
        entry.stats.reset_all();
    }

    // Read input
    let input_data = fs::read(&args.input).unwrap_or_else(|e| {
        eprintln!("failed to read input: {e}");
        process::exit(1);
    });

    let engine = PolicyEngine::new();

    let output = match args.signal.as_str() {
        "log" => process_logs(&engine, &snapshot, &input_data).await,
        "metric" => process_metrics(&engine, &snapshot, &input_data).await,
        "trace" => process_traces(&engine, &snapshot, &input_data).await,
        other => {
            eprintln!("unknown signal: {other}");
            process::exit(1);
        }
    };

    // Write output
    fs::write(&args.output, &output).unwrap_or_else(|e| {
        eprintln!("failed to write output: {e}");
        process::exit(1);
    });

    // Write stats
    write_stats(&args.stats, &registry);
}
