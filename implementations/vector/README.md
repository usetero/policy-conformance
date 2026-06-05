# Vector Implementation

Place the policy-aware Vector binary at:

```sh
implementations/vector/vector
```

The implementation harness renders `config.template.yaml` with:

- `RECEIVER_PORT`: local OTLP/HTTP ingest port used by tests
- `SINK_PORT`: local OTLP/HTTP sink used for captured output
- `POLICIES_PATH`: absolute path to the testcase `policies.json`

Run a targeted implementation test with:

```sh
task test:impl:vector TC=logs_no_match
```
