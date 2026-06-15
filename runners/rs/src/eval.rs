use std::borrow::Cow;

use policy_rs::engine::TypedValue;
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

/// True if the AnyValue carries any value variant (string, int, bool, etc.).
/// Mirrors Go's `body.Type() != pcommon.ValueTypeEmpty` semantics.
fn any_value_present(val: Option<&otel::AnyValue>) -> bool {
    let Some(v) = val else { return false };
    v.string_value.is_some()
        || v.bool_value.is_some()
        || v.int_value.is_some()
        || v.double_value.is_some()
        || v.array_value.is_some()
        || v.kvlist_value.is_some()
        || v.bytes_value.is_some()
}

/// Presence semantics for the log_field "body": empty-string body counts as
/// missing. Non-string body kinds (kvlist, int, etc.) still count as present.
fn log_body_present(val: Option<&otel::AnyValue>) -> bool {
    let Some(v) = val else { return false };
    if let Some(s) = &v.string_value {
        return !s.is_empty();
    }
    v.bool_value.is_some()
        || v.int_value.is_some()
        || v.double_value.is_some()
        || v.array_value.is_some()
        || v.kvlist_value.is_some()
        || v.bytes_value.is_some()
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

/// Resolve an attribute path to its raw AnyValue, preserving the value's
/// native type for typed (equals/gt/gte/lt/lte) matching. Only flat paths are
/// supported — nested kvlist values are stored as raw JSON and aren't borrowed.
fn find_attribute_value<'a>(
    attrs: &'a [otel::KeyValue],
    path: &[String],
) -> Option<&'a otel::AnyValue> {
    if path.is_empty() {
        return None;
    }
    for kv in attrs {
        if kv.key != path[0] {
            continue;
        }
        if path.len() == 1 {
            return kv.value.as_ref();
        }
        return None;
    }
    None
}

/// Map an OTLP AnyValue to the engine's TypedValue so non-string matchers see
/// the value's real type. Map/slice/empty values report as absent (None),
/// which the engine treats as a non-match (fail-open).
fn any_value_typed(v: &otel::AnyValue) -> Option<TypedValue<'_>> {
    if let Some(s) = &v.string_value {
        return Some(TypedValue::String(Cow::Borrowed(s)));
    }
    if let Some(b) = v.bool_value {
        return Some(TypedValue::Bool(b));
    }
    if let Some(iv) = &v.int_value {
        let i = match iv {
            serde_json::Value::Number(n) => n.as_i64(),
            serde_json::Value::String(s) => s.parse::<i64>().ok(),
            _ => None,
        }?;
        return Some(TypedValue::Int(i));
    }
    if let Some(d) = v.double_value {
        return Some(TypedValue::Double(d));
    }
    if let Some(b) = &v.bytes_decoded {
        return Some(TypedValue::Bytes(b));
    }
    None
}

fn resource_attrs(resource: Option<&otel::Resource>) -> &[otel::KeyValue] {
    resource.map(|r| r.attributes.as_slice()).unwrap_or(&[])
}

fn scope_attrs(scope: Option<&otel::InstrumentationScope>) -> &[otel::KeyValue] {
    scope.map(|s| s.attributes.as_slice()).unwrap_or(&[])
}

/// Returns true when the attribute path resolves to a present value,
/// regardless of whether that value can be expressed as a string. This is
/// the primitive used to power `exists: true` matchers, in contrast to
/// `find_attribute_path` which only returns Some for string-typed values.
fn attribute_exists_path(attrs: &[otel::KeyValue], path: &[String]) -> bool {
    if path.is_empty() {
        return false;
    }
    for kv in attrs {
        if kv.key != path[0] {
            continue;
        }
        if path.len() == 1 {
            return any_value_present(kv.value.as_ref());
        }
        if let Some(ref val) = kv.value
            && let Some(ref kvlist) = val.kvlist_value
            && let Ok(nested) = serde_json::from_value::<KvlistValues>(kvlist.clone())
        {
            return attribute_exists_path(&nested.values, &path[1..]);
        }
        return false;
    }
    false
}

/// Remove and return the first KeyValue matching `path[0]`. Only operates on
/// the flat (single-segment) case — nested kvlist removal isn't expressed by
/// the proto's rename target.
fn remove_attr_kv(attrs: &mut Vec<otel::KeyValue>, path: &[String]) -> Option<otel::KeyValue> {
    let key = path.first()?;
    let idx = attrs.iter().position(|kv| &kv.key == key)?;
    Some(attrs.remove(idx))
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

    fn field_exists(&self, field: &LogFieldSelector) -> bool {
        match field {
            LogFieldSelector::Simple(f) => match f {
                LogField::Body => log_body_present(self.record.body.as_ref()),
                LogField::SeverityText => !self.record.severity_text.is_empty(),
                LogField::TraceId => !self.record.trace_id.is_empty(),
                LogField::SpanId => !self.record.span_id.is_empty(),
                LogField::EventName => !self.record.event_name.is_empty(),
                LogField::ResourceSchemaUrl => !self.resource_schema_url.is_empty(),
                LogField::ScopeSchemaUrl => !self.scope_schema_url.is_empty(),
                _ => false,
            },
            LogFieldSelector::LogAttribute(path) => {
                attribute_exists_path(&self.record.attributes, path)
            }
            LogFieldSelector::ResourceAttribute(path) => attribute_exists_path(
                self.resource
                    .as_ref()
                    .map(|r| r.attributes.as_slice())
                    .unwrap_or(&[]),
                path,
            ),
            LogFieldSelector::ScopeAttribute(path) => attribute_exists_path(
                self.scope
                    .as_ref()
                    .map(|s| s.attributes.as_slice())
                    .unwrap_or(&[]),
                path,
            ),
        }
    }

    fn get_typed_value(&self, field: &LogFieldSelector) -> Option<TypedValue<'_>> {
        match field {
            LogFieldSelector::Simple(f) => match f {
                LogField::Body => self.record.body.as_ref().and_then(any_value_typed),
                LogField::TraceId => self
                    .record
                    .trace_id_bytes
                    .as_deref()
                    .map(TypedValue::Bytes)
                    .or_else(|| non_empty(&self.record.trace_id).map(TypedValue::String)),
                LogField::SpanId => self
                    .record
                    .span_id_bytes
                    .as_deref()
                    .map(TypedValue::Bytes)
                    .or_else(|| non_empty(&self.record.span_id).map(TypedValue::String)),
                LogField::SeverityText => {
                    non_empty(&self.record.severity_text).map(TypedValue::String)
                }
                LogField::EventName => non_empty(&self.record.event_name).map(TypedValue::String),
                LogField::ResourceSchemaUrl => {
                    non_empty(self.resource_schema_url).map(TypedValue::String)
                }
                LogField::ScopeSchemaUrl => {
                    non_empty(self.scope_schema_url).map(TypedValue::String)
                }
                _ => None,
            },
            LogFieldSelector::LogAttribute(path) => {
                find_attribute_value(&self.record.attributes, path).and_then(any_value_typed)
            }
            LogFieldSelector::ResourceAttribute(path) => find_attribute_value(
                self.resource
                    .as_ref()
                    .map(|r| r.attributes.as_slice())
                    .unwrap_or(&[]),
                path,
            )
            .and_then(any_value_typed),
            LogFieldSelector::ScopeAttribute(path) => find_attribute_value(
                self.scope
                    .as_ref()
                    .map(|s| s.attributes.as_slice())
                    .unwrap_or(&[]),
                path,
            )
            .and_then(any_value_typed),
        }
    }
}

impl Transformable for MutLogContext<'_> {
    fn set_field(&mut self, field: &LogFieldSelector, value: &str) {
        match field {
            LogFieldSelector::Simple(f) => match f {
                LogField::Body => {
                    self.record.body = Some(otel::AnyValue {
                        string_value: Some(value.to_string()),
                        ..Default::default()
                    });
                }
                LogField::SeverityText => self.record.severity_text = value.to_string(),
                LogField::TraceId => self.record.trace_id = value.to_string(),
                LogField::SpanId => self.record.span_id = value.to_string(),
                LogField::EventName => self.record.event_name = value.to_string(),
                _ => {}
            },
            LogFieldSelector::LogAttribute(path) => {
                set_string_attr(&mut self.record.attributes, path, value);
            }
            LogFieldSelector::ResourceAttribute(path) => {
                if let Some(ref mut r) = self.resource {
                    set_string_attr(&mut r.attributes, path, value);
                }
            }
            LogFieldSelector::ScopeAttribute(path) => {
                if let Some(ref mut s) = self.scope {
                    set_string_attr(&mut s.attributes, path, value);
                }
            }
        }
    }

    fn delete_field(&mut self, field: &LogFieldSelector) -> bool {
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
            LogFieldSelector::ResourceAttribute(path) => self
                .resource
                .as_deref_mut()
                .map(|r| remove_attr(&mut r.attributes, path))
                .unwrap_or(false),
            LogFieldSelector::ScopeAttribute(path) => self
                .scope
                .as_deref_mut()
                .map(|s| remove_attr(&mut s.attributes, path))
                .unwrap_or(false),
        }
    }

    fn move_field(&mut self, from: &LogFieldSelector, to: &LogFieldSelector) {
        // Engine guarantees `from` exists and that upsert preconditions on
        // `to` are satisfied. Remove the underlying KeyValue (preserving the
        // OTel value type), then re-insert it under `to`'s key in `to`'s
        // namespace — overwriting any existing entry at the target key
        // (which matches Go's pcommon.Map.PutEmpty semantics for upsert).
        let source_kv = match from {
            LogFieldSelector::LogAttribute(path) => {
                remove_attr_kv(&mut self.record.attributes, path)
            }
            LogFieldSelector::ResourceAttribute(path) => self
                .resource
                .as_deref_mut()
                .and_then(|r| remove_attr_kv(&mut r.attributes, path)),
            LogFieldSelector::ScopeAttribute(path) => self
                .scope
                .as_deref_mut()
                .and_then(|s| remove_attr_kv(&mut s.attributes, path)),
            _ => None,
        };
        let Some(mut kv) = source_kv else {
            return;
        };
        let target_key = match to {
            LogFieldSelector::LogAttribute(path)
            | LogFieldSelector::ResourceAttribute(path)
            | LogFieldSelector::ScopeAttribute(path) => path.first().cloned(),
            _ => None,
        };
        let Some(key) = target_key else {
            return;
        };
        kv.key = key.clone();
        match to {
            LogFieldSelector::LogAttribute(_) => {
                self.record.attributes.retain(|x| x.key != key);
                self.record.attributes.push(kv);
            }
            LogFieldSelector::ResourceAttribute(_) => {
                if let Some(ref mut r) = self.resource {
                    r.attributes.retain(|x| x.key != key);
                    r.attributes.push(kv);
                }
            }
            LogFieldSelector::ScopeAttribute(_) => {
                if let Some(ref mut s) = self.scope {
                    s.attributes.retain(|x| x.key != key);
                    s.attributes.push(kv);
                }
            }
            _ => {}
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

/// Set or overwrite an attribute value as a string. Used by the engine for
/// add/redact dispatch — both paths land in a string-typed value.
fn set_string_attr(attrs: &mut Vec<otel::KeyValue>, path: &[String], value: &str) {
    let Some(key) = attr_path(path) else {
        return;
    };
    if let Some(kv) = attrs.iter_mut().find(|kv| kv.key == key) {
        kv.value = Some(otel::AnyValue {
            string_value: Some(value.to_string()),
            ..Default::default()
        });
        return;
    }
    attrs.push(otel::KeyValue {
        key: key.to_string(),
        value: Some(otel::AnyValue {
            string_value: Some(value.to_string()),
            ..Default::default()
        }),
    });
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

    fn field_exists(&self, field: &MetricFieldSelector) -> bool {
        match field {
            MetricFieldSelector::DatapointAttribute(path) => {
                attribute_exists_path(self.datapoint_attributes, path)
            }
            MetricFieldSelector::ResourceAttribute(path) => {
                attribute_exists_path(resource_attrs(self.resource), path)
            }
            MetricFieldSelector::ScopeAttribute(path) => {
                attribute_exists_path(scope_attrs(self.scope), path)
            }
            // Simple fields and Type/Temporality are all string-valued — the
            // default (get_field().is_some()) is correct.
            _ => self.get_field(field).is_some(),
        }
    }

    fn get_typed_value(&self, field: &MetricFieldSelector) -> Option<TypedValue<'_>> {
        match field {
            MetricFieldSelector::DatapointAttribute(path) => {
                find_attribute_value(self.datapoint_attributes, path).and_then(any_value_typed)
            }
            MetricFieldSelector::ResourceAttribute(path) => {
                find_attribute_value(resource_attrs(self.resource), path).and_then(any_value_typed)
            }
            MetricFieldSelector::ScopeAttribute(path) => {
                find_attribute_value(scope_attrs(self.scope), path).and_then(any_value_typed)
            }
            // Name/description/unit/type/temporality/scope are string-valued.
            _ => self.get_field(field).map(TypedValue::String),
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

    fn field_exists(&self, field: &TraceFieldSelector) -> bool {
        match field {
            TraceFieldSelector::SpanAttribute(path) => {
                attribute_exists_path(&self.span.attributes, path)
            }
            TraceFieldSelector::ResourceAttribute(path) => {
                attribute_exists_path(resource_attrs(self.resource), path)
            }
            TraceFieldSelector::ScopeAttribute(path) => {
                attribute_exists_path(scope_attrs(self.scope), path)
            }
            // Other trace fields are string-valued; the default is correct.
            _ => self.get_field(field).is_some(),
        }
    }

    fn get_typed_value(&self, field: &TraceFieldSelector) -> Option<TypedValue<'_>> {
        match field {
            TraceFieldSelector::Simple(f) => match f {
                TraceField::TraceId => self
                    .span
                    .trace_id_bytes
                    .as_deref()
                    .map(TypedValue::Bytes)
                    .or_else(|| non_empty(&self.span.trace_id).map(TypedValue::String)),
                TraceField::SpanId => self
                    .span
                    .span_id_bytes
                    .as_deref()
                    .map(TypedValue::Bytes)
                    .or_else(|| non_empty(&self.span.span_id).map(TypedValue::String)),
                TraceField::ParentSpanId => self
                    .span
                    .parent_span_id_bytes
                    .as_deref()
                    .map(TypedValue::Bytes)
                    .or_else(|| non_empty(&self.span.parent_span_id).map(TypedValue::String)),
                _ => self.get_field(field).map(TypedValue::String),
            },
            TraceFieldSelector::SpanAttribute(path) => {
                find_attribute_value(&self.span.attributes, path).and_then(any_value_typed)
            }
            TraceFieldSelector::ResourceAttribute(path) => {
                find_attribute_value(resource_attrs(self.resource), path).and_then(any_value_typed)
            }
            TraceFieldSelector::ScopeAttribute(path) => {
                find_attribute_value(scope_attrs(self.scope), path).and_then(any_value_typed)
            }
            _ => self.get_field(field).map(TypedValue::String),
        }
    }
}

impl Transformable for MutTraceContext<'_> {
    fn set_field(&mut self, field: &TraceFieldSelector, value: &str) {
        if matches!(field, TraceFieldSelector::SamplingThreshold) {
            let sub_kv = format!("th:{value}");
            self.span.trace_state = merge_ot_tracestate(&self.span.trace_state, &sub_kv);
        }
        // Other trace transforms are not exercised by the conformance suite.
    }

    fn delete_field(&mut self, _field: &TraceFieldSelector) -> bool {
        false
    }

    fn move_field(&mut self, _from: &TraceFieldSelector, _to: &TraceFieldSelector) {}
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
