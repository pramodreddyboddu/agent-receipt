# OpenTelemetry (OTLP/JSON) trace export

`agent-receipt export --format otlp` writes one trace file in the [OTLP/JSON](https://opentelemetry.io/docs/specs/otlp/) `ExportTraceServiceRequest` shape: `resourceSpans`, then `scopeSpans`, then `spans`. `--format otel` is the same writer.

The file is for the collector and the tracing tools you already run. agent-receipt does not open a socket, does not run an OTLP/HTTP client, and does not install a collector.

```bash
agent-receipt export --format otlp
agent-receipt export --format otel last --out trace.otlp.json
agent-receipt export --format otlp --session my-session
agent-receipt export --format otlp .agent-receipt/my-session.session
```

A receipt becomes `receipt.otlp.json` beside the `.md` file. `--session <id>` writes `<id>.otlp.json` beside `outDir` (`.agent-receipt/<id>.otlp.json` by default). A `*.session` directory, or its `session-manifest.json`, uses the same tree and writes beside the package. `--out` names the file. A trailing slash, or an existing directory, receives the default file name inside it.

## What is in the file

| Piece | Value |
| --- | --- |
| Resource `service.name` | `agent-receipt` |
| Resource `service.version` | This package version |
| Resource `host.name` | Host label of the trace-root receipt, when it has one |
| Resource `vcs.repository.url.full` | `Remote` of the trace-root receipt, when it has one |
| Scope | name `agent-receipt`, same version |
| `traceId` | First 16 bytes of the trace-root receipt sha256 (32 lowercase hex) |
| Root span | `agent.run`. Agent, adapter, risk, max severity, failed-on, gate exit, signed, receipt sha256, and hash-chain position when the audit log has that hash |
| Child spans | Commands and tool calls, including MCP, in recorded order. Name, exit code, and `STATUS_CODE_ERROR` when the exit is non-zero or a policy pack denied that call |
| `spanId` | First 8 bytes of sha256(`receiptSha:index`) (16 lowercase hex). Index 0 is the receipt |
| Session | One trace. The root receipt is the root span. Each child receipt is an `agent.run` span with `parentSpanId` set. Host is an attribute on that span |
| Time | `startTimeUnixNano` and `endTimeUnixNano` are decimal strings. A child with no recorded time uses the parent start. `agent_receipt.index` keeps order |

Attribute values use the OTLP JSON `AnyValue` shape: `stringValue`, `intValue` as a decimal string, or `boolValue`. Keys follow OpenTelemetry semantic conventions where one fits (`service.name`, `host.name`, `gen_ai.agent.name`, `gen_ai.tool.name`, `process.command_line`). Fields that are ours use the `agent_receipt.` prefix.

The same inputs write the same bytes. Key order is fixed. The file does not contain a wall-clock timestamp of the export.

`traceId` and `spanId` are lowercase hex, which is what the OTLP/JSON mapping uses. They are not base64. An empty `parentSpanId` means a root span.

## Redaction

OTLP always redacts, the same way `export --format intoto` always redacts. There is no `--no-redact` on either format. HTML and Markdown redact only when you pass `--redact`.

OTLP masks secrets in commands, arguments, host labels, and tool-call inputs (AWS keys, GitHub tokens, and the other patterns `share` uses). A host label or repository URL that is not a secret stays, so a session can still show `host-a` and `https://github.com/org/repo`. `--redact` on OTLP is accepted and changes nothing. `--include-host` is not accepted: that flag is the HTML and Markdown choice between masking the whole Host line and keeping it. OTLP does not copy diff bodies.

## Integrity

The receipt hash is checked before the file is opened for writing. A tampered receipt exits 2 and leaves no `.otlp.json` and no temporary file. Usage errors (unknown format, `--no-redact`, a missing receipt) exit 1 and also write nothing. This command does not append `.agent-receipt/audit.jsonl`.

## Load the file

Point the OpenTelemetry Collector `otlpjsonfile` receiver at the file, then export to the backend you already use. `start_at: beginning` reads the document once.

```yaml
receivers:
  otlpjsonfile:
    include:
      - /path/to/receipt.otlp.json
    start_at: beginning
exporters:
  otlp/jaeger:
    endpoint: jaeger:4317
    tls:
      insecure: true
service:
  pipelines:
    traces:
      receivers: [otlpjsonfile]
      exporters: [otlp/jaeger]
```

Swap the exporter for Grafana Tempo, Honeycomb, or Datadog. Those products take OTLP from the collector. agent-receipt does not push to them.

`otel-cli` sends spans to a collector. It does not import this file. Use the `otlpjsonfile` receiver above as the load path.

Jaeger and Tempo then show one trace per receipt, or one trace for a session, with `agent.run` at the root and a child span per command or tool call.

Schema: [`otlp-trace.schema.json`](otlp-trace.schema.json).
