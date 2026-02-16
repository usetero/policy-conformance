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
	Record   *logspb.LogRecord
	Resource *resourcepb.Resource
	Scope    *commonpb.InstrumentationScope
}

type MetricContext struct {
	Metric              *metricspb.Metric
	DatapointAttributes []*commonpb.KeyValue
	Resource            *resourcepb.Resource
	Scope               *commonpb.InstrumentationScope
}

type TraceContext struct {
	Span     *tracepb.Span
	Resource *resourcepb.Resource
	Scope    *commonpb.InstrumentationScope
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
	key := attrPath(ref)
	if key == "" {
		return nil
	}
	return findAttribute(attrs, key)
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
	key := metricAttrPath(ref)
	if key == "" {
		return nil
	}
	return findAttribute(attrs, key)
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
	key := traceAttrPath(ref)
	if key == "" {
		return nil
	}
	return findAttribute(attrs, key)
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
