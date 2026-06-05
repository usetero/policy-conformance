package main

import (
	"flag"
	"fmt"
	"os"

	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
)

func main() {
	signal := flag.String("signal", "", "signal type: log/logs, metric/metrics, trace/traces")
	input := flag.String("input", "", "input OTLP JSON path")
	output := flag.String("output", "", "output OTLP protobuf path")
	flag.Parse()

	if *signal == "" || *input == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "usage: otlpjson2proto --signal <log|metric|trace> --input input.json --output output.pb")
		os.Exit(2)
	}

	data, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read input: %v\n", err)
		os.Exit(1)
	}

	var out []byte
	switch *signal {
	case "log", "logs":
		req := plogotlp.NewExportRequest()
		if err := req.UnmarshalJSON(data); err != nil {
			fmt.Fprintf(os.Stderr, "unmarshal logs: %v\n", err)
			os.Exit(1)
		}
		out, err = req.MarshalProto()
	case "metric", "metrics":
		req := pmetricotlp.NewExportRequest()
		if err := req.UnmarshalJSON(data); err != nil {
			fmt.Fprintf(os.Stderr, "unmarshal metrics: %v\n", err)
			os.Exit(1)
		}
		out, err = req.MarshalProto()
	case "trace", "traces":
		req := ptraceotlp.NewExportRequest()
		if err := req.UnmarshalJSON(data); err != nil {
			fmt.Fprintf(os.Stderr, "unmarshal traces: %v\n", err)
			os.Exit(1)
		}
		out, err = req.MarshalProto()
	default:
		fmt.Fprintf(os.Stderr, "unknown signal: %s\n", *signal)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal protobuf: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, out, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write output: %v\n", err)
		os.Exit(1)
	}
}
