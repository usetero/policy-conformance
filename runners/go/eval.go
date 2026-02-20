package main

import (
	"github.com/usetero/policy-go"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// ─── Context types ───────────────────────────────────────────────────

type LogContext struct {
	Record            *logspb.LogRecord
	Resource          *resourcepb.Resource
	Scope             *commonpb.InstrumentationScope
	ResourceSchemaURL string
	ScopeSchemaURL    string
}

type MetricContext struct {
	Metric              *metricspb.Metric
	DatapointAttributes []*commonpb.KeyValue
	Resource            *resourcepb.Resource
	Scope               *commonpb.InstrumentationScope
	ResourceSchemaURL   string
	ScopeSchemaURL      string
}

type TraceContext struct {
	Span              *tracepb.Span
	Resource          *resourcepb.Resource
	Scope             *commonpb.InstrumentationScope
	ResourceSchemaURL string
	ScopeSchemaURL    string
}

// ─── Attribute helpers ───────────────────────────────────────────────

func findAttribute(attrs []*commonpb.KeyValue, key string) []byte {
	for _, kv := range attrs {
		if kv.Key == key {
			return anyValueBytes(kv.Value)
		}
	}
	return nil
}

func findAttributePath(attrs []*commonpb.KeyValue, path []string) []byte {
	if len(path) == 0 {
		return nil
	}
	for _, kv := range attrs {
		if kv.Key != path[0] {
			continue
		}
		if len(path) == 1 {
			return anyValueBytes(kv.Value)
		}
		// Traverse into nested kvlist
		if kv.Value != nil {
			if kvl, ok := kv.Value.Value.(*commonpb.AnyValue_KvlistValue); ok && kvl.KvlistValue != nil {
				return findAttributePath(kvl.KvlistValue.Values, path[1:])
			}
		}
		return nil
	}
	return nil
}

func anyValueBytes(v *commonpb.AnyValue) []byte {
	if v == nil {
		return nil
	}
	switch val := v.Value.(type) {
	case *commonpb.AnyValue_StringValue:
		if val.StringValue == "" {
			return nil
		}
		return []byte(val.StringValue)
	default:
		return nil
	}
}

func resourceAttrs(r *resourcepb.Resource) []*commonpb.KeyValue {
	if r == nil {
		return nil
	}
	return r.Attributes
}

func scopeAttrs(s *commonpb.InstrumentationScope) []*commonpb.KeyValue {
	if s == nil {
		return nil
	}
	return s.Attributes
}

func attrPath(ref policy.LogFieldRef) string {
	if len(ref.AttrPath) > 0 {
		return ref.AttrPath[0]
	}
	return ""
}

func metricAttrPath(ref policy.MetricFieldRef) string {
	if len(ref.AttrPath) > 0 {
		return ref.AttrPath[0]
	}
	return ""
}

func traceAttrPath(ref policy.TraceFieldRef) string {
	if len(ref.AttrPath) > 0 {
		return ref.AttrPath[0]
	}
	return ""
}

// ─── Log matcher ─────────────────────────────────────────────────────

func OTelLogMatcher(ctx *LogContext, ref policy.LogFieldRef) []byte {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			return anyValueBytes(ctx.Record.Body)
		case policy.LogFieldSeverityText:
			if ctx.Record.SeverityText == "" {
				return nil
			}
			return []byte(ctx.Record.SeverityText)
		case policy.LogFieldTraceID:
			if len(ctx.Record.TraceId) == 0 {
				return nil
			}
			return ctx.Record.TraceId
		case policy.LogFieldSpanID:
			if len(ctx.Record.SpanId) == 0 {
				return nil
			}
			return ctx.Record.SpanId
		case policy.LogFieldEventName:
			if ctx.Record.EventName == "" {
				return nil
			}
			return []byte(ctx.Record.EventName)
		case policy.LogFieldResourceSchemaURL:
			if ctx.ResourceSchemaURL == "" {
				return nil
			}
			return []byte(ctx.ResourceSchemaURL)
		case policy.LogFieldScopeSchemaURL:
			if ctx.ScopeSchemaURL == "" {
				return nil
			}
			return []byte(ctx.ScopeSchemaURL)
		default:
			return nil
		}
	}

	var attrs []*commonpb.KeyValue
	switch {
	case ref.IsRecordAttr():
		attrs = ctx.Record.Attributes
	case ref.IsResourceAttr():
		attrs = resourceAttrs(ctx.Resource)
	case ref.IsScopeAttr():
		attrs = scopeAttrs(ctx.Scope)
	default:
		return nil
	}
	return findAttributePath(attrs, ref.AttrPath)
}

// ─── Metric matcher ──────────────────────────────────────────────────

func OTelMetricMatcher(ctx *MetricContext, ref policy.MetricFieldRef) []byte {
	if ref.IsField() {
		switch ref.Field {
		case policy.MetricFieldName:
			if ctx.Metric.Name == "" {
				return nil
			}
			return []byte(ctx.Metric.Name)
		case policy.MetricFieldDescription:
			if ctx.Metric.Description == "" {
				return nil
			}
			return []byte(ctx.Metric.Description)
		case policy.MetricFieldUnit:
			if ctx.Metric.Unit == "" {
				return nil
			}
			return []byte(ctx.Metric.Unit)
		case policy.MetricFieldType:
			return []byte(metricType(ctx.Metric))
		case policy.MetricFieldAggregationTemporality:
			return []byte(aggregationTemporality(ctx.Metric))
		case policy.MetricFieldScopeName:
			if ctx.Scope == nil || ctx.Scope.Name == "" {
				return nil
			}
			return []byte(ctx.Scope.Name)
		case policy.MetricFieldScopeVersion:
			if ctx.Scope == nil || ctx.Scope.Version == "" {
				return nil
			}
			return []byte(ctx.Scope.Version)
		case policy.MetricFieldResourceSchemaURL:
			if ctx.ResourceSchemaURL == "" {
				return nil
			}
			return []byte(ctx.ResourceSchemaURL)
		case policy.MetricFieldScopeSchemaURL:
			if ctx.ScopeSchemaURL == "" {
				return nil
			}
			return []byte(ctx.ScopeSchemaURL)
		default:
			return nil
		}
	}

	var attrs []*commonpb.KeyValue
	switch {
	case ref.IsRecordAttr():
		attrs = ctx.DatapointAttributes
	case ref.IsResourceAttr():
		attrs = resourceAttrs(ctx.Resource)
	case ref.IsScopeAttr():
		attrs = scopeAttrs(ctx.Scope)
	default:
		return nil
	}
	return findAttributePath(attrs, ref.AttrPath)
}

func metricType(m *metricspb.Metric) string {
	switch m.Data.(type) {
	case *metricspb.Metric_Gauge:
		return "gauge"
	case *metricspb.Metric_Sum:
		return "sum"
	case *metricspb.Metric_Histogram:
		return "histogram"
	case *metricspb.Metric_ExponentialHistogram:
		return "exponential_histogram"
	case *metricspb.Metric_Summary:
		return "summary"
	default:
		return ""
	}
}

func aggregationTemporality(m *metricspb.Metric) string {
	switch d := m.Data.(type) {
	case *metricspb.Metric_Sum:
		return temporalityString(d.Sum.AggregationTemporality)
	case *metricspb.Metric_Histogram:
		return temporalityString(d.Histogram.AggregationTemporality)
	case *metricspb.Metric_ExponentialHistogram:
		return temporalityString(d.ExponentialHistogram.AggregationTemporality)
	default:
		return ""
	}
}

func temporalityString(t metricspb.AggregationTemporality) string {
	switch t {
	case metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA:
		return "delta"
	case metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE:
		return "cumulative"
	default:
		return ""
	}
}

// ─── Trace matcher ───────────────────────────────────────────────────

func OTelTraceMatcher(ctx *TraceContext, ref policy.TraceFieldRef) []byte {
	if ref.IsField() {
		switch ref.Field {
		case policy.TraceFieldName:
			if ctx.Span.Name == "" {
				return nil
			}
			return []byte(ctx.Span.Name)
		case policy.TraceFieldTraceID:
			if len(ctx.Span.TraceId) == 0 {
				return nil
			}
			return ctx.Span.TraceId
		case policy.TraceFieldSpanID:
			if len(ctx.Span.SpanId) == 0 {
				return nil
			}
			return ctx.Span.SpanId
		case policy.TraceFieldParentSpanID:
			if len(ctx.Span.ParentSpanId) == 0 {
				return nil
			}
			return ctx.Span.ParentSpanId
		case policy.TraceFieldTraceState:
			if ctx.Span.TraceState == "" {
				return nil
			}
			return []byte(ctx.Span.TraceState)
		case policy.TraceFieldKind:
			return []byte(spanKindString(ctx.Span.Kind))
		case policy.TraceFieldStatus:
			if ctx.Span.Status == nil {
				return nil
			}
			return []byte(statusCodeString(ctx.Span.Status.Code))
		case policy.TraceFieldEventName:
			for _, evt := range ctx.Span.Events {
				if evt.Name != "" {
					return []byte(evt.Name)
				}
			}
			return nil
		case policy.TraceFieldScopeName:
			if ctx.Scope == nil || ctx.Scope.Name == "" {
				return nil
			}
			return []byte(ctx.Scope.Name)
		case policy.TraceFieldScopeVersion:
			if ctx.Scope == nil || ctx.Scope.Version == "" {
				return nil
			}
			return []byte(ctx.Scope.Version)
		case policy.TraceFieldResourceSchemaURL:
			if ctx.ResourceSchemaURL == "" {
				return nil
			}
			return []byte(ctx.ResourceSchemaURL)
		case policy.TraceFieldScopeSchemaURL:
			if ctx.ScopeSchemaURL == "" {
				return nil
			}
			return []byte(ctx.ScopeSchemaURL)
		default:
			return nil
		}
	}

	var attrs []*commonpb.KeyValue
	switch {
	case ref.IsRecordAttr():
		attrs = ctx.Span.Attributes
	case ref.IsResourceAttr():
		attrs = resourceAttrs(ctx.Resource)
	case ref.IsScopeAttr():
		attrs = scopeAttrs(ctx.Scope)
	default:
		return nil
	}
	return findAttributePath(attrs, ref.AttrPath)
}

func spanKindString(k tracepb.Span_SpanKind) string {
	switch k {
	case tracepb.Span_SPAN_KIND_INTERNAL:
		return "internal"
	case tracepb.Span_SPAN_KIND_SERVER:
		return "server"
	case tracepb.Span_SPAN_KIND_CLIENT:
		return "client"
	case tracepb.Span_SPAN_KIND_PRODUCER:
		return "producer"
	case tracepb.Span_SPAN_KIND_CONSUMER:
		return "consumer"
	default:
		return ""
	}
}

func statusCodeString(c tracepb.Status_StatusCode) string {
	switch c {
	case tracepb.Status_STATUS_CODE_OK:
		return "ok"
	case tracepb.Status_STATUS_CODE_ERROR:
		return "error"
	case tracepb.Status_STATUS_CODE_UNSET:
		return "unset"
	default:
		return ""
	}
}

// ─── Log transformer ─────────────────────────────────────────────────

func OTelLogTransformer(ctx *LogContext, op policy.TransformOp) bool {
	switch op.Kind {
	case policy.TransformRemove:
		return otelLogRemove(ctx, op.Ref)
	case policy.TransformRedact:
		return otelLogRedact(ctx, op.Ref, op.Value)
	case policy.TransformRename:
		return otelLogRename(ctx, op.Ref, op.To, op.Upsert)
	case policy.TransformAdd:
		return otelLogAdd(ctx, op.Ref, op.Value, op.Upsert)
	}
	return false
}

func otelLogRemove(ctx *LogContext, ref policy.LogFieldRef) bool {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			hit := ctx.Record.Body != nil
			ctx.Record.Body = nil
			return hit
		case policy.LogFieldSeverityText:
			hit := ctx.Record.SeverityText != ""
			ctx.Record.SeverityText = ""
			return hit
		case policy.LogFieldTraceID:
			hit := len(ctx.Record.TraceId) > 0
			ctx.Record.TraceId = nil
			return hit
		case policy.LogFieldSpanID:
			hit := len(ctx.Record.SpanId) > 0
			ctx.Record.SpanId = nil
			return hit
		case policy.LogFieldEventName:
			hit := ctx.Record.EventName != ""
			ctx.Record.EventName = ""
			return hit
		}
		return false
	}
	return removeAttribute(otelLogAttrs(ctx, ref), attrPath(ref))
}

func otelLogRedact(ctx *LogContext, ref policy.LogFieldRef, replacement string) bool {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			hit := ctx.Record.Body != nil
			ctx.Record.Body = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: replacement}}
			return hit
		case policy.LogFieldSeverityText:
			hit := ctx.Record.SeverityText != ""
			ctx.Record.SeverityText = replacement
			return hit
		case policy.LogFieldTraceID:
			hit := len(ctx.Record.TraceId) > 0
			ctx.Record.TraceId = []byte(replacement)
			return hit
		case policy.LogFieldSpanID:
			hit := len(ctx.Record.SpanId) > 0
			ctx.Record.SpanId = []byte(replacement)
			return hit
		case policy.LogFieldEventName:
			hit := ctx.Record.EventName != ""
			ctx.Record.EventName = replacement
			return hit
		}
		return false
	}
	attrs := otelLogAttrs(ctx, ref)
	key := attrPath(ref)
	if attrs == nil || key == "" {
		return false
	}
	idx := findAttributeIndex(*attrs, key)
	if idx < 0 {
		return false
	}
	(*attrs)[idx].Value = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: replacement}}
	return true
}

func otelLogRename(ctx *LogContext, ref policy.LogFieldRef, to string, upsert bool) bool {
	if ref.IsField() {
		return false // renaming fixed fields not supported
	}
	attrs := otelLogAttrs(ctx, ref)
	key := attrPath(ref)
	if key == "" {
		return false
	}
	idx := findAttributeIndex(*attrs, key)
	if idx < 0 {
		return false
	}
	val := anyValueBytes((*attrs)[idx].Value)
	if !upsert {
		if findAttributeIndex(*attrs, to) >= 0 {
			return true // source existed but target blocked
		}
	}
	// Remove source
	*attrs = append((*attrs)[:idx], (*attrs)[idx+1:]...)
	// Set target
	if val != nil {
		setAttribute(attrs, to, string(val), true)
	} else {
		setAttribute(attrs, to, "", true)
	}
	return true
}

func otelLogAdd(ctx *LogContext, ref policy.LogFieldRef, value string, upsert bool) bool {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			if !upsert && ctx.Record.Body != nil {
				return true
			}
			ctx.Record.Body = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}}
			return true
		case policy.LogFieldSeverityText:
			if !upsert && ctx.Record.SeverityText != "" {
				return true
			}
			ctx.Record.SeverityText = value
			return true
		case policy.LogFieldTraceID:
			if !upsert && len(ctx.Record.TraceId) > 0 {
				return true
			}
			ctx.Record.TraceId = []byte(value)
			return true
		case policy.LogFieldSpanID:
			if !upsert && len(ctx.Record.SpanId) > 0 {
				return true
			}
			ctx.Record.SpanId = []byte(value)
			return true
		case policy.LogFieldEventName:
			if !upsert && ctx.Record.EventName != "" {
				return true
			}
			ctx.Record.EventName = value
			return true
		}
		return false
	}
	return setAttribute(otelLogAttrs(ctx, ref), attrPath(ref), value, upsert)
}

func otelLogAttrs(ctx *LogContext, ref policy.LogFieldRef) *[]*commonpb.KeyValue {
	switch {
	case ref.IsRecordAttr():
		return &ctx.Record.Attributes
	case ref.IsResourceAttr():
		if ctx.Resource == nil {
			return nil
		}
		return &ctx.Resource.Attributes
	case ref.IsScopeAttr():
		if ctx.Scope == nil {
			return nil
		}
		return &ctx.Scope.Attributes
	}
	return nil
}

func findAttributeIndex(attrs []*commonpb.KeyValue, key string) int {
	for i, kv := range attrs {
		if kv.Key == key {
			return i
		}
	}
	return -1
}

func removeAttribute(attrs *[]*commonpb.KeyValue, key string) bool {
	if attrs == nil || key == "" {
		return false
	}
	idx := findAttributeIndex(*attrs, key)
	if idx < 0 {
		return false
	}
	*attrs = append((*attrs)[:idx], (*attrs)[idx+1:]...)
	return true
}

func setAttribute(attrs *[]*commonpb.KeyValue, key, value string, upsert bool) bool {
	if attrs == nil || key == "" {
		return false
	}
	idx := findAttributeIndex(*attrs, key)
	if idx >= 0 {
		if !upsert {
			return true // exists but not overwriting
		}
		(*attrs)[idx].Value = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}}
		return true
	}
	*attrs = append(*attrs, &commonpb.KeyValue{
		Key:   key,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}},
	})
	return true
}

// ─── Datapoint attribute helpers ─────────────────────────────────────

func getDatapointAttrs(m *metricspb.Metric) []*commonpb.KeyValue {
	switch d := m.Data.(type) {
	case *metricspb.Metric_Gauge:
		if len(d.Gauge.DataPoints) > 0 {
			return d.Gauge.DataPoints[0].Attributes
		}
	case *metricspb.Metric_Sum:
		if len(d.Sum.DataPoints) > 0 {
			return d.Sum.DataPoints[0].Attributes
		}
	case *metricspb.Metric_Histogram:
		if len(d.Histogram.DataPoints) > 0 {
			return d.Histogram.DataPoints[0].Attributes
		}
	case *metricspb.Metric_ExponentialHistogram:
		if len(d.ExponentialHistogram.DataPoints) > 0 {
			return d.ExponentialHistogram.DataPoints[0].Attributes
		}
	case *metricspb.Metric_Summary:
		if len(d.Summary.DataPoints) > 0 {
			return d.Summary.DataPoints[0].Attributes
		}
	}
	return nil
}
