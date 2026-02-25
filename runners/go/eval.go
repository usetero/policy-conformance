package main

import (
	"encoding/hex"
	"strings"

	"github.com/usetero/policy-go"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// ─── Context types ───────────────────────────────────────────────────

type LogContext struct {
	Record            plog.LogRecord
	Resource          pcommon.Resource
	Scope             pcommon.InstrumentationScope
	ResourceSchemaURL string
	ScopeSchemaURL    string
}

type MetricContext struct {
	Metric              pmetric.Metric
	DatapointAttributes pcommon.Map
	Resource            pcommon.Resource
	Scope               pcommon.InstrumentationScope
	ResourceSchemaURL   string
	ScopeSchemaURL      string
}

type TraceContext struct {
	Span              ptrace.Span
	Resource          pcommon.Resource
	Scope             pcommon.InstrumentationScope
	ResourceSchemaURL string
	ScopeSchemaURL    string
}

// ─── Attribute helpers ───────────────────────────────────────────────

func findAttribute(attrs pcommon.Map, key string) []byte {
	v, ok := attrs.Get(key)
	if !ok {
		return nil
	}
	return valueBytes(v)
}

func findAttributePath(attrs pcommon.Map, path []string) []byte {
	if len(path) == 0 {
		return nil
	}
	v, ok := attrs.Get(path[0])
	if !ok {
		return nil
	}
	if len(path) == 1 {
		return valueBytes(v)
	}
	if v.Type() == pcommon.ValueTypeMap {
		return findAttributePath(v.Map(), path[1:])
	}
	return nil
}

func valueBytes(v pcommon.Value) []byte {
	if v.Type() != pcommon.ValueTypeStr {
		return nil
	}
	s := v.Str()
	if s == "" {
		return nil
	}
	return []byte(s)
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
			return valueBytes(ctx.Record.Body())
		case policy.LogFieldSeverityText:
			if ctx.Record.SeverityText() == "" {
				return nil
			}
			return []byte(ctx.Record.SeverityText())
		case policy.LogFieldTraceID:
			id := ctx.Record.TraceID()
			if id.IsEmpty() {
				return nil
			}
			return []byte(hex.EncodeToString(id[:]))
		case policy.LogFieldSpanID:
			id := ctx.Record.SpanID()
			if id.IsEmpty() {
				return nil
			}
			return []byte(hex.EncodeToString(id[:]))
		case policy.LogFieldEventName:
			if ctx.Record.EventName() == "" {
				return nil
			}
			return []byte(ctx.Record.EventName())
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

	var attrs pcommon.Map
	switch {
	case ref.IsRecordAttr():
		attrs = ctx.Record.Attributes()
	case ref.IsResourceAttr():
		attrs = ctx.Resource.Attributes()
	case ref.IsScopeAttr():
		attrs = ctx.Scope.Attributes()
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
			if ctx.Metric.Name() == "" {
				return nil
			}
			return []byte(ctx.Metric.Name())
		case policy.MetricFieldDescription:
			if ctx.Metric.Description() == "" {
				return nil
			}
			return []byte(ctx.Metric.Description())
		case policy.MetricFieldUnit:
			if ctx.Metric.Unit() == "" {
				return nil
			}
			return []byte(ctx.Metric.Unit())
		case policy.MetricFieldType:
			return []byte(metricType(ctx.Metric))
		case policy.MetricFieldAggregationTemporality:
			return []byte(aggregationTemporality(ctx.Metric))
		case policy.MetricFieldScopeName:
			if ctx.Scope.Name() == "" {
				return nil
			}
			return []byte(ctx.Scope.Name())
		case policy.MetricFieldScopeVersion:
			if ctx.Scope.Version() == "" {
				return nil
			}
			return []byte(ctx.Scope.Version())
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

	var attrs pcommon.Map
	switch {
	case ref.IsRecordAttr():
		attrs = ctx.DatapointAttributes
	case ref.IsResourceAttr():
		attrs = ctx.Resource.Attributes()
	case ref.IsScopeAttr():
		attrs = ctx.Scope.Attributes()
	default:
		return nil
	}
	return findAttributePath(attrs, ref.AttrPath)
}

func metricType(m pmetric.Metric) string {
	switch m.Type() {
	case pmetric.MetricTypeGauge:
		return "gauge"
	case pmetric.MetricTypeSum:
		return "sum"
	case pmetric.MetricTypeHistogram:
		return "histogram"
	case pmetric.MetricTypeExponentialHistogram:
		return "exponential_histogram"
	case pmetric.MetricTypeSummary:
		return "summary"
	default:
		return ""
	}
}

func aggregationTemporality(m pmetric.Metric) string {
	switch m.Type() {
	case pmetric.MetricTypeSum:
		return temporalityString(m.Sum().AggregationTemporality())
	case pmetric.MetricTypeHistogram:
		return temporalityString(m.Histogram().AggregationTemporality())
	case pmetric.MetricTypeExponentialHistogram:
		return temporalityString(m.ExponentialHistogram().AggregationTemporality())
	default:
		return ""
	}
}

func temporalityString(t pmetric.AggregationTemporality) string {
	switch t {
	case pmetric.AggregationTemporalityDelta:
		return "delta"
	case pmetric.AggregationTemporalityCumulative:
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
			if ctx.Span.Name() == "" {
				return nil
			}
			return []byte(ctx.Span.Name())
		case policy.TraceFieldTraceID:
			id := ctx.Span.TraceID()
			if id.IsEmpty() {
				return nil
			}
			return []byte(hex.EncodeToString(id[:]))
		case policy.TraceFieldSpanID:
			id := ctx.Span.SpanID()
			if id.IsEmpty() {
				return nil
			}
			return []byte(hex.EncodeToString(id[:]))
		case policy.TraceFieldParentSpanID:
			id := ctx.Span.ParentSpanID()
			if id.IsEmpty() {
				return nil
			}
			return []byte(hex.EncodeToString(id[:]))
		case policy.TraceFieldTraceState:
			ts := ctx.Span.TraceState().AsRaw()
			if ts == "" {
				return nil
			}
			return []byte(ts)
		case policy.TraceFieldKind:
			return []byte(spanKindString(ctx.Span.Kind()))
		case policy.TraceFieldStatus:
			return []byte(statusCodeString(ctx.Span.Status().Code()))
		case policy.TraceFieldEventName:
			for i := 0; i < ctx.Span.Events().Len(); i++ {
				name := ctx.Span.Events().At(i).Name()
				if name != "" {
					return []byte(name)
				}
			}
			return nil
		case policy.TraceFieldScopeName:
			if ctx.Scope.Name() == "" {
				return nil
			}
			return []byte(ctx.Scope.Name())
		case policy.TraceFieldScopeVersion:
			if ctx.Scope.Version() == "" {
				return nil
			}
			return []byte(ctx.Scope.Version())
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

	var attrs pcommon.Map
	switch {
	case ref.IsRecordAttr():
		attrs = ctx.Span.Attributes()
	case ref.IsResourceAttr():
		attrs = ctx.Resource.Attributes()
	case ref.IsScopeAttr():
		attrs = ctx.Scope.Attributes()
	default:
		return nil
	}
	return findAttributePath(attrs, ref.AttrPath)
}

func spanKindString(k ptrace.SpanKind) string {
	switch k {
	case ptrace.SpanKindInternal:
		return "internal"
	case ptrace.SpanKindServer:
		return "server"
	case ptrace.SpanKindClient:
		return "client"
	case ptrace.SpanKindProducer:
		return "producer"
	case ptrace.SpanKindConsumer:
		return "consumer"
	default:
		return ""
	}
}

func statusCodeString(c ptrace.StatusCode) string {
	switch c {
	case ptrace.StatusCodeOk:
		return "ok"
	case ptrace.StatusCodeError:
		return "error"
	case ptrace.StatusCodeUnset:
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
			hit := ctx.Record.Body().Type() != pcommon.ValueTypeEmpty
			ctx.Record.Body().SetStr("")
			return hit
		case policy.LogFieldSeverityText:
			hit := ctx.Record.SeverityText() != ""
			ctx.Record.SetSeverityText("")
			return hit
		case policy.LogFieldTraceID:
			hit := !ctx.Record.TraceID().IsEmpty()
			ctx.Record.SetTraceID(pcommon.NewTraceIDEmpty())
			return hit
		case policy.LogFieldSpanID:
			hit := !ctx.Record.SpanID().IsEmpty()
			ctx.Record.SetSpanID(pcommon.NewSpanIDEmpty())
			return hit
		case policy.LogFieldEventName:
			hit := ctx.Record.EventName() != ""
			ctx.Record.SetEventName("")
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
			hit := ctx.Record.Body().Type() != pcommon.ValueTypeEmpty
			ctx.Record.Body().SetStr(replacement)
			return hit
		case policy.LogFieldSeverityText:
			hit := ctx.Record.SeverityText() != ""
			ctx.Record.SetSeverityText(replacement)
			return hit
		case policy.LogFieldTraceID:
			hit := !ctx.Record.TraceID().IsEmpty()
			ctx.Record.SetTraceID(traceIDFromString(replacement))
			return hit
		case policy.LogFieldSpanID:
			hit := !ctx.Record.SpanID().IsEmpty()
			ctx.Record.SetSpanID(spanIDFromString(replacement))
			return hit
		case policy.LogFieldEventName:
			hit := ctx.Record.EventName() != ""
			ctx.Record.SetEventName(replacement)
			return hit
		}
		return false
	}
	attrs := otelLogAttrs(ctx, ref)
	key := attrPath(ref)
	if key == "" {
		return false
	}
	_, ok := attrs.Get(key)
	if !ok {
		return false
	}
	attrs.PutStr(key, replacement)
	return true
}

func otelLogRename(ctx *LogContext, ref policy.LogFieldRef, to string, upsert bool) bool {
	if ref.IsField() {
		return false
	}
	attrs := otelLogAttrs(ctx, ref)
	key := attrPath(ref)
	if key == "" {
		return false
	}
	v, ok := attrs.Get(key)
	if !ok {
		return false
	}
	val := valueBytes(v)
	if !upsert {
		if _, exists := attrs.Get(to); exists {
			return true
		}
	}
	attrs.RemoveIf(func(k string, v pcommon.Value) bool {
		return k == key
	})
	if val != nil {
		attrs.PutStr(to, string(val))
	} else {
		attrs.PutStr(to, "")
	}
	return true
}

func otelLogAdd(ctx *LogContext, ref policy.LogFieldRef, value string, upsert bool) bool {
	if ref.IsField() {
		switch ref.Field {
		case policy.LogFieldBody:
			if !upsert && ctx.Record.Body().Type() != pcommon.ValueTypeEmpty {
				return true
			}
			ctx.Record.Body().SetStr(value)
			return true
		case policy.LogFieldSeverityText:
			if !upsert && ctx.Record.SeverityText() != "" {
				return true
			}
			ctx.Record.SetSeverityText(value)
			return true
		case policy.LogFieldTraceID:
			if !upsert && !ctx.Record.TraceID().IsEmpty() {
				return true
			}
			ctx.Record.SetTraceID(traceIDFromString(value))
			return true
		case policy.LogFieldSpanID:
			if !upsert && !ctx.Record.SpanID().IsEmpty() {
				return true
			}
			ctx.Record.SetSpanID(spanIDFromString(value))
			return true
		case policy.LogFieldEventName:
			if !upsert && ctx.Record.EventName() != "" {
				return true
			}
			ctx.Record.SetEventName(value)
			return true
		}
		return false
	}
	return setAttribute(otelLogAttrs(ctx, ref), attrPath(ref), value, upsert)
}

func otelLogAttrs(ctx *LogContext, ref policy.LogFieldRef) pcommon.Map {
	switch {
	case ref.IsRecordAttr():
		return ctx.Record.Attributes()
	case ref.IsResourceAttr():
		return ctx.Resource.Attributes()
	case ref.IsScopeAttr():
		return ctx.Scope.Attributes()
	}
	return pcommon.NewMap()
}

func removeAttribute(attrs pcommon.Map, key string) bool {
	if key == "" {
		return false
	}
	_, ok := attrs.Get(key)
	if !ok {
		return false
	}
	attrs.RemoveIf(func(k string, v pcommon.Value) bool {
		return k == key
	})
	return true
}

func setAttribute(attrs pcommon.Map, key, value string, upsert bool) bool {
	if key == "" {
		return false
	}
	if _, ok := attrs.Get(key); ok {
		if !upsert {
			return true
		}
		attrs.PutStr(key, value)
		return true
	}
	attrs.PutStr(key, value)
	return true
}

// ─── Trace transformer ──────────────────────────────────────────────

func OTelTraceTransformer(ctx *TraceContext, ref policy.TraceFieldRef, value string) {
	if ref.Field == policy.SpanSamplingThreshold().Field {
		ctx.Span.TraceState().FromRaw(mergeOTTracestate(ctx.Span.TraceState().AsRaw(), "th:"+value))
	}
}

func mergeOTTracestate(tracestate, subkv string) string {
	subKey := subkv
	if idx := strings.Index(subkv, ":"); idx >= 0 {
		subKey = subkv[:idx]
	}

	var otParts []string
	var otherVendors []string

	if tracestate != "" {
		for _, vendor := range strings.Split(tracestate, ",") {
			vendor = strings.TrimSpace(vendor)
			if vendor == "" {
				continue
			}
			if strings.HasPrefix(vendor, "ot=") {
				otValue := vendor[3:]
				for _, part := range strings.Split(otValue, ";") {
					part = strings.TrimSpace(part)
					if part == "" {
						continue
					}
					partKey := part
					if idx := strings.Index(part, ":"); idx >= 0 {
						partKey = part[:idx]
					}
					if partKey != subKey {
						otParts = append(otParts, part)
					}
				}
			} else {
				otherVendors = append(otherVendors, vendor)
			}
		}
	}

	otParts = append(otParts, subkv)
	result := "ot=" + strings.Join(otParts, ";")
	if len(otherVendors) > 0 {
		result += "," + strings.Join(otherVendors, ",")
	}
	return result
}

// ─── Datapoint attribute helpers ─────────────────────────────────────

func getDatapointAttrs(m pmetric.Metric) pcommon.Map {
	switch m.Type() {
	case pmetric.MetricTypeGauge:
		if m.Gauge().DataPoints().Len() > 0 {
			return m.Gauge().DataPoints().At(0).Attributes()
		}
	case pmetric.MetricTypeSum:
		if m.Sum().DataPoints().Len() > 0 {
			return m.Sum().DataPoints().At(0).Attributes()
		}
	case pmetric.MetricTypeHistogram:
		if m.Histogram().DataPoints().Len() > 0 {
			return m.Histogram().DataPoints().At(0).Attributes()
		}
	case pmetric.MetricTypeExponentialHistogram:
		if m.ExponentialHistogram().DataPoints().Len() > 0 {
			return m.ExponentialHistogram().DataPoints().At(0).Attributes()
		}
	case pmetric.MetricTypeSummary:
		if m.Summary().DataPoints().Len() > 0 {
			return m.Summary().DataPoints().At(0).Attributes()
		}
	}
	return pcommon.NewMap()
}

// ─── ID conversion helpers ──────────────────────────────────────────

func traceIDFromString(s string) pcommon.TraceID {
	var id pcommon.TraceID
	b, err := hex.DecodeString(s)
	if err == nil && len(b) == 16 {
		copy(id[:], b)
	}
	return id
}

func spanIDFromString(s string) pcommon.SpanID {
	var id pcommon.SpanID
	b, err := hex.DecodeString(s)
	if err == nil && len(b) == 8 {
		copy(id[:], b)
	}
	return id
}
