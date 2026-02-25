use std::borrow::Cow;

use policy_rs::proto::tero::policy::v1::{LogField, MetricField, TraceField};
use policy_rs::{
    LogFieldSelector, LogSignal, Matchable, MetricFieldSelector, MetricSignal, TraceFieldSelector,
    TraceSignal, Transformable,
};
use serde::Deserialize;

use crate::otel;

// ─── Context types ───────────────────────────────────────────────────

pub struct MetricContext<'a> {
    pub metric: &'a otel::Metric,
    pub datapoint_attributes: &'a [otel::KeyValue],
    pub resource: Option<&'a otel::Resource>,
    pub scope: Option<&'a otel::InstrumentationScope>,
    pub resource_schema_url: &'a str,
    pub scope_schema_url: &'a str,
}

// ─── Attribute helpers ───────────────────────────────────────────────

fn any_value_string(val: Option<&otel::AnyValue>) -> Option<Cow<'_, str>> {
    let v = val?;
    match &v.string_value {
        Some(s) if !s.is_empty() => Some(Cow::Borrowed(s.as_str())),
        _ => None,
    }
}

fn find_attribute_path<'a>(attrs: &'a [otel::KeyValue], path: &[String]) -> Option<Cow<'a, str>> {
    if path.is_empty() {
        return None;
    }
    for kv in attrs {
        if kv.key != path[0] {
            continue;
        }
        if path.len() == 1 {
            return any_value_string(kv.value.as_ref());
        }
        // Traverse into nested kvlist
        if let Some(ref val) = kv.value {
            if let Some(ref kvlist) = val.kvlist_value {
                if let Ok(nested) = serde_json::from_value::<KvlistValues>(kvlist.clone()) {
                    return find_attribute_path_owned(&nested.values, &path[1..]);
                }
            }
        }
        return None;
    }
    None
}

#[derive(Deserialize)]
struct KvlistValues {
    values: Vec<otel::KeyValue>,
}

fn find_attribute_path_owned(attrs: &[otel::KeyValue], path: &[String]) -> Option<Cow<'static, str>> {
    if path.is_empty() {
        return None;
    }
    for kv in attrs {
        if kv.key != path[0] {
            continue;
        }
        if path.len() == 1 {
            if let Some(ref val) = kv.value {
                if let Some(ref s) = val.string_value {
                    if !s.is_empty() {
                        return Some(Cow::Owned(s.clone()));
                    }
                }
            }
            return None;
        }
        if let Some(ref val) = kv.value {
            if let Some(ref kvlist) = val.kvlist_value {
                if let Ok(nested) = serde_json::from_value::<KvlistValues>(kvlist.clone()) {
                    return find_attribute_path_owned(&nested.values, &path[1..]);
                }
            }
        }
        return None;
    }
    None
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

// ─── Log Context ─────────────────────────────────────────────────────

pub struct MutLogContext<'a> {
    pub record: &'a mut otel::LogRecord,
    pub resource: Option<&'a mut otel::Resource>,
    pub scope: Option<&'a mut otel::InstrumentationScope>,
    pub resource_schema_url: &'a str,
    pub scope_schema_url: &'a str,
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
                LogField::EventName => non_empty(&self.record.event_name),
                LogField::ResourceSchemaUrl => non_empty(self.resource_schema_url),
                LogField::ScopeSchemaUrl => non_empty(self.scope_schema_url),
                _ => None,
            },
            LogFieldSelector::LogAttribute(path) => {
                find_attribute_path(&self.record.attributes, path)
            }
            LogFieldSelector::ResourceAttribute(path) => {
                find_attribute_path(
                    self.resource
                        .as_ref()
                        .map(|r| r.attributes.as_slice())
                        .unwrap_or(&[]),
                    path,
                )
            }
            LogFieldSelector::ScopeAttribute(path) => {
                find_attribute_path(
                    self.scope
                        .as_ref()
                        .map(|s| s.attributes.as_slice())
                        .unwrap_or(&[]),
                    path,
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
                MetricField::ScopeName => {
                    self.scope.as_ref().and_then(|s| non_empty(&s.name))
                }
                MetricField::ScopeVersion => {
                    self.scope.as_ref().and_then(|s| non_empty(&s.version))
                }
                MetricField::ResourceSchemaUrl => non_empty(self.resource_schema_url),
                MetricField::ScopeSchemaUrl => non_empty(self.scope_schema_url),
                _ => None,
            },
            MetricFieldSelector::DatapointAttribute(path) => {
                find_attribute_path(self.datapoint_attributes, path)
            }
            MetricFieldSelector::ResourceAttribute(path) => {
                find_attribute_path(resource_attrs(self.resource), path)
            }
            MetricFieldSelector::ScopeAttribute(path) => {
                find_attribute_path(scope_attrs(self.scope), path)
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

/// Shared trace field resolution used by both immutable and mutable trace contexts.
fn resolve_trace_field<'a>(
    span: &'a otel::Span,
    resource: Option<&'a otel::Resource>,
    scope: Option<&'a otel::InstrumentationScope>,
    resource_schema_url: &'a str,
    scope_schema_url: &'a str,
    field: &TraceFieldSelector,
) -> Option<Cow<'a, str>> {
    match field {
        TraceFieldSelector::Simple(f) => match f {
            TraceField::Name => non_empty(&span.name),
            TraceField::TraceId => non_empty(&span.trace_id),
            TraceField::SpanId => non_empty(&span.span_id),
            TraceField::ParentSpanId => non_empty(&span.parent_span_id),
            TraceField::TraceState => non_empty(&span.trace_state),
            TraceField::ScopeName => scope.as_ref().and_then(|s| non_empty(&s.name)),
            TraceField::ScopeVersion => scope.as_ref().and_then(|s| non_empty(&s.version)),
            TraceField::ResourceSchemaUrl => non_empty(resource_schema_url),
            TraceField::ScopeSchemaUrl => non_empty(scope_schema_url),
            _ => None,
        },
        TraceFieldSelector::SpanAttribute(path) => find_attribute_path(&span.attributes, path),
        TraceFieldSelector::ResourceAttribute(path) => {
            find_attribute_path(resource_attrs(resource), path)
        }
        TraceFieldSelector::ScopeAttribute(path) => {
            find_attribute_path(scope_attrs(scope), path)
        }
        TraceFieldSelector::SpanKind => non_empty(&span.kind),
        TraceFieldSelector::SpanStatus => {
            let status = span.status.as_ref()?;
            // Map OTel StatusCode to policy SpanStatusCode string format
            match status.code.as_str() {
                "STATUS_CODE_OK" => Some(Cow::Borrowed("SPAN_STATUS_CODE_OK")),
                "STATUS_CODE_ERROR" => Some(Cow::Borrowed("SPAN_STATUS_CODE_ERROR")),
                "STATUS_CODE_UNSET" => Some(Cow::Borrowed("SPAN_STATUS_CODE_UNSPECIFIED")),
                _ => None,
            }
        }
        TraceFieldSelector::EventName => {
            // Check span events for matching event name
            for evt in &span.events {
                if let Some(name) = evt.get("name").and_then(|v| v.as_str()) {
                    if !name.is_empty() {
                        return Some(Cow::Owned(name.to_string()));
                    }
                }
            }
            None
        }
        TraceFieldSelector::EventAttribute(_)
        | TraceFieldSelector::LinkTraceId
        | TraceFieldSelector::SamplingThreshold => None,
    }
}

// ─── Trace Context ───────────────────────────────────────────────────

pub struct MutTraceContext<'a> {
    pub span: &'a mut otel::Span,
    pub resource: Option<&'a otel::Resource>,
    pub scope: Option<&'a otel::InstrumentationScope>,
    pub resource_schema_url: &'a str,
    pub scope_schema_url: &'a str,
}

impl Matchable for MutTraceContext<'_> {
    type Signal = TraceSignal;

    fn get_field(&self, field: &TraceFieldSelector) -> Option<Cow<'_, str>> {
        resolve_trace_field(
            self.span,
            self.resource,
            self.scope,
            self.resource_schema_url,
            self.scope_schema_url,
            field,
        )
    }
}

impl Transformable for MutTraceContext<'_> {
    fn remove_field(&mut self, _field: &TraceFieldSelector) -> bool {
        false // not needed for sampling
    }

    fn redact_field(&mut self, _field: &TraceFieldSelector, _replacement: &str) -> bool {
        false // not needed for sampling
    }

    fn rename_field(&mut self, _from: &TraceFieldSelector, _to: &str, _upsert: bool) -> bool {
        false // not needed for sampling
    }

    fn add_field(&mut self, field: &TraceFieldSelector, value: &str, _upsert: bool) -> bool {
        if matches!(field, TraceFieldSelector::SamplingThreshold) {
            let sub_kv = format!("th:{value}");
            self.span.trace_state = merge_ot_tracestate(&self.span.trace_state, &sub_kv);
            true
        } else {
            false
        }
    }
}

/// Merge an OpenTelemetry sub-key (e.g. "th:8000") into a W3C tracestate
/// string under the "ot" vendor key.
fn merge_ot_tracestate(tracestate: &str, sub_kv: &str) -> String {
    let sub_key = sub_kv.split(':').next().unwrap_or(sub_kv);

    let mut ot_parts: Vec<&str> = Vec::new();
    let mut other_vendors: Vec<&str> = Vec::new();

    if !tracestate.is_empty() {
        for vendor in tracestate.split(',') {
            let vendor = vendor.trim();
            if vendor.is_empty() {
                continue;
            }
            if let Some(ot_value) = vendor.strip_prefix("ot=") {
                for part in ot_value.split(';') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    let part_key = part.split(':').next().unwrap_or(part);
                    if part_key != sub_key {
                        ot_parts.push(part);
                    }
                }
            } else {
                other_vendors.push(vendor);
            }
        }
    }

    let mut result = format!("ot={}", ot_parts.join(";"));
    if !ot_parts.is_empty() {
        result.push(';');
    }
    result.push_str(sub_kv);
    if !other_vendors.is_empty() {
        result.push(',');
        result.push_str(&other_vendors.join(","));
    }
    result
}
