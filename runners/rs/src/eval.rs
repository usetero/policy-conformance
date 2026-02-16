use std::borrow::Cow;

use policy_rs::proto::tero::policy::v1::{LogField, MetricField, TraceField};
use policy_rs::{
    LogFieldSelector, LogSignal, Matchable, MetricFieldSelector, MetricSignal, TraceFieldSelector,
    TraceSignal,
};

use crate::otel;

// ─── Context types ───────────────────────────────────────────────────

pub struct LogContext<'a> {
    pub record: &'a otel::LogRecord,
    pub resource: Option<&'a otel::Resource>,
    pub scope: Option<&'a otel::InstrumentationScope>,
}

pub struct MetricContext<'a> {
    pub metric: &'a otel::Metric,
    pub datapoint_attributes: &'a [otel::KeyValue],
    pub resource: Option<&'a otel::Resource>,
    pub scope: Option<&'a otel::InstrumentationScope>,
}

pub struct TraceContext<'a> {
    pub span: &'a otel::Span,
    pub resource: Option<&'a otel::Resource>,
    pub scope: Option<&'a otel::InstrumentationScope>,
}

// ─── Attribute helpers ───────────────────────────────────────────────

fn find_attribute<'a>(attrs: &'a [otel::KeyValue], key: &str) -> Option<Cow<'a, str>> {
    for kv in attrs {
        if kv.key == key {
            return any_value_string(kv.value.as_ref());
        }
    }
    None
}

fn any_value_string(val: Option<&otel::AnyValue>) -> Option<Cow<'_, str>> {
    let v = val?;
    match &v.string_value {
        Some(s) if !s.is_empty() => Some(Cow::Borrowed(s.as_str())),
        _ => None,
    }
}

fn resource_attrs(resource: Option<&otel::Resource>) -> &[otel::KeyValue] {
    resource.map(|r| r.attributes.as_slice()).unwrap_or(&[])
}

fn scope_attrs(scope: Option<&otel::InstrumentationScope>) -> &[otel::KeyValue] {
    scope.map(|s| s.attributes.as_slice()).unwrap_or(&[])
}

fn attr_path(path: &[String]) -> Option<&str> {
    path.first().map(|s| s.as_str())
}

fn non_empty(s: &str) -> Option<Cow<'_, str>> {
    if s.is_empty() {
        None
    } else {
        Some(Cow::Borrowed(s))
    }
}

// ─── Log Matchable ───────────────────────────────────────────────────

impl Matchable for LogContext<'_> {
    type Signal = LogSignal;

    fn get_field(&self, field: &LogFieldSelector) -> Option<Cow<'_, str>> {
        match field {
            LogFieldSelector::Simple(f) => match f {
                LogField::Body => any_value_string(self.record.body.as_ref()),
                LogField::SeverityText => non_empty(&self.record.severity_text),
                LogField::TraceId => non_empty(&self.record.trace_id),
                LogField::SpanId => non_empty(&self.record.span_id),
                _ => None,
            },
            LogFieldSelector::LogAttribute(path) => {
                let key = attr_path(path)?;
                find_attribute(&self.record.attributes, key)
            }
            LogFieldSelector::ResourceAttribute(path) => {
                let key = attr_path(path)?;
                find_attribute(resource_attrs(self.resource), key)
            }
            LogFieldSelector::ScopeAttribute(path) => {
                let key = attr_path(path)?;
                find_attribute(scope_attrs(self.scope), key)
            }
        }
    }
}

// ─── Metric Matchable ────────────────────────────────────────────────

impl Matchable for MetricContext<'_> {
    type Signal = MetricSignal;

    fn get_field(&self, field: &MetricFieldSelector) -> Option<Cow<'_, str>> {
        match field {
            MetricFieldSelector::Simple(f) => match f {
                MetricField::Name => non_empty(&self.metric.name),
                MetricField::Description => non_empty(&self.metric.description),
                MetricField::Unit => non_empty(&self.metric.unit),
                _ => None,
            },
            MetricFieldSelector::DatapointAttribute(path) => {
                let key = attr_path(path)?;
                find_attribute(self.datapoint_attributes, key)
            }
            MetricFieldSelector::ResourceAttribute(path) => {
                let key = attr_path(path)?;
                find_attribute(resource_attrs(self.resource), key)
            }
            MetricFieldSelector::ScopeAttribute(path) => {
                let key = attr_path(path)?;
                find_attribute(scope_attrs(self.scope), key)
            }
            MetricFieldSelector::Type => {
                let data = self.metric.data.as_ref()?;
                Some(Cow::Borrowed(data.metric_type()))
            }
            MetricFieldSelector::Temporality => {
                let data = self.metric.data.as_ref()?;
                data.aggregation_temporality().map(Cow::Borrowed)
            }
        }
    }
}

// ─── Trace Matchable ─────────────────────────────────────────────────

impl Matchable for TraceContext<'_> {
    type Signal = TraceSignal;

    fn get_field(&self, field: &TraceFieldSelector) -> Option<Cow<'_, str>> {
        match field {
            TraceFieldSelector::Simple(f) => match f {
                TraceField::Name => non_empty(&self.span.name),
                TraceField::TraceId => non_empty(&self.span.trace_id),
                TraceField::SpanId => non_empty(&self.span.span_id),
                TraceField::ParentSpanId => non_empty(&self.span.parent_span_id),
                TraceField::TraceState => non_empty(&self.span.trace_state),
                _ => None,
            },
            TraceFieldSelector::SpanAttribute(path) => {
                let key = attr_path(path)?;
                find_attribute(&self.span.attributes, key)
            }
            TraceFieldSelector::ResourceAttribute(path) => {
                let key = attr_path(path)?;
                find_attribute(resource_attrs(self.resource), key)
            }
            TraceFieldSelector::ScopeAttribute(path) => {
                let key = attr_path(path)?;
                find_attribute(scope_attrs(self.scope), key)
            }
            TraceFieldSelector::SpanKind => non_empty(&self.span.kind),
            TraceFieldSelector::SpanStatus => {
                let status = self.span.status.as_ref()?;
                // Map OTel StatusCode to policy SpanStatusCode string format
                match status.code.as_str() {
                    "STATUS_CODE_OK" => Some(Cow::Borrowed("SPAN_STATUS_CODE_OK")),
                    "STATUS_CODE_ERROR" => Some(Cow::Borrowed("SPAN_STATUS_CODE_ERROR")),
                    "STATUS_CODE_UNSET" => Some(Cow::Borrowed("SPAN_STATUS_CODE_UNSET")),
                    _ => None,
                }
            }
            TraceFieldSelector::EventName
            | TraceFieldSelector::EventAttribute(_)
            | TraceFieldSelector::LinkTraceId
            | TraceFieldSelector::SamplingThreshold => None,
        }
    }
}
