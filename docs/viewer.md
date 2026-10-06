# Local viewer

`agent-receipt view` is a read-only browser for receipts and linked session
trees. It uses `node:http` only. There is no runtime dependency, no CDN, and
no call out to the network.

## Local use

From a repo that already has receipts:

```bash
agent-receipt view
agent-receipt view --port 0 --open
agent-receipt view --json
agent-receipt view --receipts .agent-receipt/receipts
```

The default bind is `127.0.0.1` port `4173`. `--port 0` picks a free port and
prints the URL. `--json` prints one line and keeps serving:

```json
{"url":"http://127.0.0.1:4173/","port":4173,"receiptCount":2,"pid":12345}
```

`--open` tries the default browser (`open` on macOS, `cmd /c start` on
Windows, `xdg-open` elsewhere). If that program is missing, the command
still serves.

A host other than `127.0.0.1`, `localhost`, or `::1` is refused unless you
also pass `--allow-remote`. That flag prints a warning. The viewer is meant
to stay on the loopback interface.

`--trusted-key <fp>` and `--require-sig` use the same rules as `verify`.
Hash failure is `FAILED`. With `--require-sig`, a missing, invalid, or
untrusted signature is `FAILED` too. Without `--require-sig`, an unsigned
receipt whose hash matches is `OK`, and the signature block still says
whether a sidecar is present.

Stop the server with Ctrl+C.

## Pages

The list shows time, agent, adapter, risk, exit, signed or unsigned, verify
status, and policy-pack hits. Filters are agent, risk, signed, failed, and
text search.

A receipt shows commands, files touched, tool calls, the gate result, policy
hits, Ed25519 signature status, keyless and in-toto presence (no
certificates and no private keys), and the audit hash-chain position.

Linked receipts (v1.0.28 parent/child, v1.0.29 host labels) are a session
tree. Host labels stay visible. A host string that is itself a secret is
still masked.

Policy hits are the `## Policy packs` table already stamped on the receipt.
Opening the viewer does not re-run the pack against the working tree.

## Static CI artifact

```bash
agent-receipt view --static ./viewer-dist
```

That writes `index.html` and `data.json` and exits. It does not listen.
CSS and script are inline. There is no external font and no `http://` or
`https://` asset. Open `index.html` from disk (`file://`) or upload the
directory as a CI artifact. The same receipts write the same bytes.

`--json` with `--static` prints one object (`command`, `ok`, `static`,
`out`, `receiptCount`) and does not start a server. Do not pass `--port`,
`--host`, `--open`, or `--allow-remote` with `--static`.

## HTTP API

| Method and path | Body |
|-----------------|------|
| `GET /` | The page |
| `GET /api/receipts` | `{ "receipts": [ ... ] }` |
| `GET /api/receipts/:id` | `{ "receipt": { ... } }` |
| `GET /api/sessions` | `{ "sessions": [ ... ] }` |
| `GET /api/verify/:id` | `{ "id", "status", "ok", "reason", "exitCode", "sha256", "signature" }` |

`status` is `OK` or `FAILED`. Any method other than `GET` returns 405 with
`Allow: GET`. Unknown routes return 404 JSON. Error bodies are the fixed
strings `not found`, `forbidden`, and `method not allowed`. They do not echo
the request path.

`:id` is the receipt's link id (`r-` plus 16 hex) or its sha256. It is
looked up in an in-memory index built when the process starts. A filesystem
path is never an id. `..`, encoded `..`, a second encoding of `..`, a
backslash, and an absolute path are rejected.

## Security model

- Redaction always runs, through the same `redact.ts` path as share and
  report, before a byte is served or written. `--no-redact` is rejected
  (`view always redacts. There is no --no-redact.`).
- Host labels are kept (`maskHost: false`) so the session tree can show
  `laptop` and `runner`. Every served string, including the host, then goes
  through the secret masks. Nested receipt bodies are still omitted.
- Verification reads the original receipt bytes. The page shows the redacted
  fields. A tampered body is `FAILED`, never `OK`.
- `Content-Security-Policy` is `default-src 'none'` plus the sha256 of the
  inline style and the inline script. The live server also sets
  `connect-src 'self'` so the page can fetch `/api`. The static page sets
  `connect-src 'none'` and embeds the snapshot. The same policy is in a
  `<meta>` tag and, while serving, the HTTP header.
- `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` are
  set on every response.
- The `Host` header must equal the bound host and port (`[::1]:port` when
  the bind is IPv6). Anything else is 403. That blocks a DNS rebinding
  client that sends a public Host to the loopback port.
- Receipt text is inserted with `textContent` (and `escapeHtml` for the
  embedded snapshot). The page does not use `eval` or `innerHTML`.

`doctor` reports this as an INFO `viewer` row. The row is not a failure
under `--strict`.
