use std::borrow::Cow;

use policy_rs::proto::tero::policy::v1::{LogField, MetricField, TraceField};
use policy_rs::{
    LogFieldSelector, LogSignal, Matchable, MetricFieldSelector, MetricSignal, TraceFieldSelector,
    TraceSignal, Transformable,
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

// ─── Mutable Log Context (for transforms) ────────────────────────────

pub struct MutLogContext<'a> {
    pub record: &'a mut otel::LogRecord,
    pub resource: Option<&'a mut otel::Resource>,
    pub scope: Option<&'a mut otel::InstrumentationScope>,
}

impl Matchable for MutLogContext<'_> {
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
                find_attribute(
                    self.resource
                        .as_ref()
                        .map(|r| r.attributes.as_slice())
                        .unwrap_or(&[]),
                    key,
                )
            }
            LogFieldSelector::ScopeAttribute(path) => {
                let key = attr_path(path)?;
                find_attribute(
                    self.scope
                        .as_ref()
                        .map(|s| s.attributes.as_slice())
                        .unwrap_or(&[]),
                    key,
                )
            }
        }
    }
}

impl Transformable for MutLogContext<'_> {
    fn remove_field(&mut self, field: &LogFieldSelector) -> bool {
        match field {
            LogFieldSelector::Simple(f) => match f {
                LogField::Body => {
                    let hit = self.record.body.is_some();
                    self.record.body = None;
                    hit
                }
                LogField::SeverityText => {
                    let hit = !self.record.severity_text.is_empty();
                    self.record.severity_text.clear();
                    hit
                }
                LogField::TraceId => {
                    let hit = !self.record.trace_id.is_empty();
                    self.record.trace_id.clear();
                    hit
                }
                LogField::SpanId => {
                    let hit = !self.record.span_id.is_empty();
                    self.record.span_id.clear();
                    hit
                }
                LogField::EventName => {
                    let hit = !self.record.event_name.is_empty();
                    self.record.event_name.clear();
                    hit
                }
                _ => false,
            },
            LogFieldSelector::LogAttribute(path) => remove_attr(&mut self.record.attributes, path),
            LogFieldSelector::ResourceAttribute(path) => {
                if let Some(ref mut r) = self.resource {
                    remove_attr(&mut r.attributes, path)
                } else {
                    false
                }
            }
            LogFieldSelector::ScopeAttribute(path) => {
                if let Some(ref mut s) = self.scope {
                    remove_attr(&mut s.attributes, path)
                } else {
                    false
                }
            }
        }
    }

    fn redact_field(&mut self, field: &LogFieldSelector, replacement: &str) -> bool {
        match field {
            LogFieldSelector::Simple(f) => match f {
                LogField::Body => {
                    let hit = self.record.body.is_some();
                    self.record.body = Some(otel::AnyValue {
                        string_value: Some(replacement.to_string()),
                        ..Default::default()
                    });
                    hit
                }
                LogField::SeverityText => {
                    let hit = !self.record.severity_text.is_empty();
                    self.record.severity_text = replacement.to_string();
                    hit
                }
                LogField::TraceId => {
                    let hit = !self.record.trace_id.is_empty();
                    self.record.trace_id = replacement.to_string();
                    hit
                }
                LogField::SpanId => {
                    let hit = !self.record.span_id.is_empty();
                    self.record.span_id = replacement.to_string();
                    hit
                }
                LogField::EventName => {
                    let hit = !self.record.event_name.is_empty();
                    self.record.event_name = replacement.to_string();
                    hit
                }
                _ => false,
            },
            LogFieldSelector::LogAttribute(path) => {
                set_attr(&mut self.record.attributes, path, replacement, true)
            }
            LogFieldSelector::ResourceAttribute(path) => {
                if let Some(ref mut r) = self.resource {
                    set_attr(&mut r.attributes, path, replacement, true)
                } else {
                    false
                }
            }
            LogFieldSelector::ScopeAttribute(path) => {
                if let Some(ref mut s) = self.scope {
                    set_attr(&mut s.attributes, path, replacement, true)
                } else {
                    false
                }
            }
        }
    }

    fn rename_field(&mut self, from: &LogFieldSelector, to: &str, upsert: bool) -> bool {
        // Only attribute renames are supported
        let (attrs, path) = match from {
            LogFieldSelector::LogAttribute(path) => (&mut self.record.attributes, path),
            LogFieldSelector::ResourceAttribute(path) => {
                if let Some(ref mut r) = self.resource {
                    (&mut r.attributes, path)
                } else {
                    return false;
                }
            }
            LogFieldSelector::ScopeAttribute(path) => {
                if let Some(ref mut s) = self.scope {
                    (&mut s.attributes, path)
                } else {
                    return false;
                }
            }
            _ => return false,
        };
        let key = match attr_path(path) {
            Some(k) => k,
            None => return false,
        };
        let idx = attrs.iter().position(|kv| kv.key == key);
        let idx = match idx {
            Some(i) => i,
            None => return false,
        };
        if !upsert && attrs.iter().any(|kv| kv.key == to) {
            return true; // source exists but target blocked
        }
        let mut removed = attrs.remove(idx);
        // Remove existing target if upsert
        if upsert {
            attrs.retain(|kv| kv.key != to);
        }
        removed.key = to.to_string();
        attrs.push(removed);
        true
    }

    fn add_field(&mut self, field: &LogFieldSelector, value: &str, upsert: bool) -> bool {
        match field {
            LogFieldSelector::Simple(f) => match f {
                LogField::Body => {
                    if !upsert && self.record.body.is_some() {
                        return true;
                    }
                    self.record.body = Some(otel::AnyValue {
                        string_value: Some(value.to_string()),
                        ..Default::default()
                    });
                    true
                }
                LogField::SeverityText => {
                    if !upsert && !self.record.severity_text.is_empty() {
                        return true;
                    }
                    self.record.severity_text = value.to_string();
                    true
                }
                LogField::TraceId => {
                    if !upsert && !self.record.trace_id.is_empty() {
                        return true;
                    }
                    self.record.trace_id = value.to_string();
                    true
                }
                LogField::SpanId => {
                    if !upsert && !self.record.span_id.is_empty() {
                        return true;
                    }
                    self.record.span_id = value.to_string();
                    true
                }
                LogField::EventName => {
                    if !upsert && !self.record.event_name.is_empty() {
                        return true;
                    }
                    self.record.event_name = value.to_string();
                    true
                }
                _ => false,
            },
            LogFieldSelector::LogAttribute(path) => {
                set_attr(&mut self.record.attributes, path, value, upsert)
            }
            LogFieldSelector::ResourceAttribute(path) => {
                if let Some(ref mut r) = self.resource {
                    set_attr(&mut r.attributes, path, value, upsert)
                } else {
                    false
                }
            }
            LogFieldSelector::ScopeAttribute(path) => {
                if let Some(ref mut s) = self.scope {
                    set_attr(&mut s.attributes, path, value, upsert)
                } else {
                    false
                }
            }
        }
    }
}

fn remove_attr(attrs: &mut Vec<otel::KeyValue>, path: &[String]) -> bool {
    let key = match attr_path(path) {
        Some(k) => k,
        None => return false,
    };
    let len_before = attrs.len();
    attrs.retain(|kv| kv.key != key);
    attrs.len() < len_before
}

fn set_attr(attrs: &mut Vec<otel::KeyValue>, path: &[String], value: &str, upsert: bool) -> bool {
    let key = match attr_path(path) {
        Some(k) => k,
        None => return false,
    };
    if let Some(kv) = attrs.iter_mut().find(|kv| kv.key == key) {
        if !upsert {
            return true; // exists but not overwriting
        }
        kv.value = Some(otel::AnyValue {
            string_value: Some(value.to_string()),
            ..Default::default()
        });
        return true;
    }
    attrs.push(otel::KeyValue {
        key: key.to_string(),
        value: Some(otel::AnyValue {
            string_value: Some(value.to_string()),
            ..Default::default()
        }),
    });
    true
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
