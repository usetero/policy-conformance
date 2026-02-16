//! OTel proto-compatible types with serde support.
//!
//! These match the JSON format produced by the Zig protobuf encoder (which is
//! the canonical format for test case input/expected files). Key differences
//! from the `opentelemetry-proto` crate:
//! - trace_id/span_id are base64 strings (not hex)
//! - span kind and status code are string enums (not integers)
//! - timestamps are numbers (not strings)
//! - severity_number is a string enum

use serde::{Deserialize, Serialize};

// ─── Common ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Resource {
    pub attributes: Vec<KeyValue>,
    pub dropped_attributes_count: u32,
    pub entity_refs: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct InstrumentationScope {
    pub name: String,
    pub version: String,
    pub attributes: Vec<KeyValue>,
    pub dropped_attributes_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyValue {
    pub key: String,
    #[serde(default)]
    pub value: Option<AnyValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct AnyValue {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub string_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bool_value: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub int_value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub double_value: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub array_value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kvlist_value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_value: Option<String>,
}

// ─── Logs ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogsData {
    pub resource_logs: Vec<ResourceLogs>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ResourceLogs {
    pub resource: Option<Resource>,
    pub scope_logs: Vec<ScopeLogs>,
    pub schema_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ScopeLogs {
    pub scope: Option<InstrumentationScope>,
    pub log_records: Vec<LogRecord>,
    pub schema_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct LogRecord {
    pub time_unix_nano: serde_json::Value,
    pub observed_time_unix_nano: serde_json::Value,
    pub severity_number: String,
    pub severity_text: String,
    pub body: Option<AnyValue>,
    pub attributes: Vec<KeyValue>,
    pub dropped_attributes_count: u32,
    pub flags: u32,
    pub trace_id: String,
    pub span_id: String,
    pub event_name: String,
}

// ─── Metrics ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricsData {
    pub resource_metrics: Vec<ResourceMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ResourceMetrics {
    pub resource: Option<Resource>,
    pub scope_metrics: Vec<ScopeMetrics>,
    pub schema_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ScopeMetrics {
    pub scope: Option<InstrumentationScope>,
    pub metrics: Vec<Metric>,
    pub schema_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Metric {
    pub name: String,
    pub description: String,
    pub unit: String,
    #[serde(default)]
    pub metadata: Vec<KeyValue>,
    #[serde(flatten)]
    pub data: Option<MetricData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MetricData {
    Gauge(Gauge),
    Sum(Sum),
    Histogram(Histogram),
    ExponentialHistogram(ExponentialHistogram),
    Summary(Summary),
}

impl MetricData {
    pub fn metric_type(&self) -> &'static str {
        match self {
            MetricData::Gauge(_) => "METRIC_TYPE_GAUGE",
            MetricData::Sum(_) => "METRIC_TYPE_SUM",
            MetricData::Histogram(_) => "METRIC_TYPE_HISTOGRAM",
            MetricData::ExponentialHistogram(_) => "METRIC_TYPE_EXPONENTIAL_HISTOGRAM",
            MetricData::Summary(_) => "METRIC_TYPE_SUMMARY",
        }
    }

    pub fn aggregation_temporality(&self) -> Option<&'static str> {
        let at = match self {
            MetricData::Sum(s) => &s.aggregation_temporality,
            MetricData::Histogram(h) => &h.aggregation_temporality,
            MetricData::ExponentialHistogram(eh) => &eh.aggregation_temporality,
            _ => return None,
        };
        match at {
            serde_json::Value::Number(n) => match n.as_i64()? {
                1 => Some("AGGREGATION_TEMPORALITY_DELTA"),
                2 => Some("AGGREGATION_TEMPORALITY_CUMULATIVE"),
                _ => None,
            },
            serde_json::Value::String(s) => match s.as_str() {
                "AGGREGATION_TEMPORALITY_DELTA" => Some("AGGREGATION_TEMPORALITY_DELTA"),
                "AGGREGATION_TEMPORALITY_CUMULATIVE" => Some("AGGREGATION_TEMPORALITY_CUMULATIVE"),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn first_datapoint_attributes(&self) -> &[KeyValue] {
        match self {
            MetricData::Gauge(g) => g
                .data_points
                .first()
                .map(|dp| dp.attributes.as_slice())
                .unwrap_or(&[]),
            MetricData::Sum(s) => s
                .data_points
                .first()
                .map(|dp| dp.attributes.as_slice())
                .unwrap_or(&[]),
            MetricData::Histogram(h) => h
                .data_points
                .first()
                .map(|dp| dp.attributes.as_slice())
                .unwrap_or(&[]),
            MetricData::ExponentialHistogram(_) => &[],
            MetricData::Summary(s) => s
                .data_points
                .first()
                .map(|dp| dp.attributes.as_slice())
                .unwrap_or(&[]),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Gauge {
    pub data_points: Vec<NumberDataPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Sum {
    pub data_points: Vec<NumberDataPoint>,
    pub aggregation_temporality: serde_json::Value,
    pub is_monotonic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Histogram {
    pub data_points: Vec<HistogramDataPoint>,
    pub aggregation_temporality: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ExponentialHistogram {
    pub data_points: Vec<serde_json::Value>,
    pub aggregation_temporality: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Summary {
    pub data_points: Vec<SummaryDataPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct NumberDataPoint {
    pub attributes: Vec<KeyValue>,
    pub start_time_unix_nano: serde_json::Value,
    pub time_unix_nano: serde_json::Value,
    pub exemplars: Vec<serde_json::Value>,
    pub flags: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_double: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_int: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct HistogramDataPoint {
    pub attributes: Vec<KeyValue>,
    pub start_time_unix_nano: serde_json::Value,
    pub time_unix_nano: serde_json::Value,
    pub count: serde_json::Value,
    pub sum: Option<f64>,
    pub bucket_counts: Vec<serde_json::Value>,
    pub explicit_bounds: Vec<f64>,
    pub exemplars: Vec<serde_json::Value>,
    pub flags: u32,
    pub min: Option<f64>,
    pub max: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SummaryDataPoint {
    pub attributes: Vec<KeyValue>,
    pub start_time_unix_nano: serde_json::Value,
    pub time_unix_nano: serde_json::Value,
    pub count: serde_json::Value,
    pub sum: Option<f64>,
}

// ─── Traces ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TracesData {
    pub resource_spans: Vec<ResourceSpans>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ResourceSpans {
    pub resource: Option<Resource>,
    pub scope_spans: Vec<ScopeSpans>,
    pub schema_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ScopeSpans {
    pub scope: Option<InstrumentationScope>,
    pub spans: Vec<Span>,
    pub schema_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Span {
    pub trace_id: String,
    pub span_id: String,
    pub trace_state: String,
    pub parent_span_id: String,
    pub flags: u32,
    pub name: String,
    pub kind: String,
    pub start_time_unix_nano: serde_json::Value,
    pub end_time_unix_nano: serde_json::Value,
    pub attributes: Vec<KeyValue>,
    pub dropped_attributes_count: u32,
    pub events: Vec<serde_json::Value>,
    pub dropped_events_count: u32,
    pub links: Vec<serde_json::Value>,
    pub dropped_links_count: u32,
    pub status: Option<Status>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct Status {
    pub message: String,
    pub code: String,
}
