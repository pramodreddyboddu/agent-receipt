# Sigstore keyless signing

`attest --keyless` signs one in-toto statement with an ephemeral P-256 key.
Fulcio binds that key to an OIDC identity. Rekor records the DSSE entry.
The private key and the OIDC token are never written and never logged.

This is not a CA. `sign --keyless` is not a command. `sign` still writes
the local Ed25519 `foo.sig.json` sidecar.

The bundle is `application/vnd.dev.sigstore.bundle.v0.3+json`, saved as
`<stem>.sigstore.json` next to the `.intoto.jsonl`. Certificate transparency
(the embedded SCT) is not checked. The time source is the Rekor integrated
time, after the signed entry timestamp and the signed checkpoint verify.

## GitHub Actions

The workflow needs `id-token: write`. The audience is `sigstore`. This
snippet is documentation. It is not installed under `.github/workflows`.

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-node@v4
    with:
      node-version: 20
  - run: npm install -g github:pramodreddyboddu/agent-receipt#v1.0.38
  - run: agent-receipt init && agent-receipt capture --agent ci
  - run: agent-receipt attest --keyless --json
  - run: >
      agent-receipt attest --verify receipt.sigstore.json
      --certificate-identity "https://github.com/ORG/REPO/.github/workflows/ci.yml@refs/heads/main"
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Use the workflow's own `job_workflow_ref` style subject. An identity that
does not match the certificate SAN fails closed.

## Token sources

Precedence is `--identity-token <file>`, then `SIGSTORE_ID_TOKEN`, then the
GitHub Actions ambient token (`ACTIONS_ID_TOKEN_REQUEST_URL` and
`ACTIONS_ID_TOKEN_REQUEST_TOKEN`, audience `sigstore`). `--identity-token -`
reads stdin. The token is sent only to Fulcio, in the JSON body.

## Verify

```bash
agent-receipt attest --verify receipt.sigstore.json \
  --certificate-identity "https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Exactly one of `--certificate-identity` or `--certificate-identity-regexp`
is required, plus `--certificate-oidc-issuer`. Missing either fails closed
(exit 1). A bad signature, identity, issuer, chain, or integrated time
exits 2.

The default trust root is the embedded public-good Fulcio intermediate and
root, plus the current Rekor public key. `--trusted-root <file>` replaces
that set. The file is Sigstore `trusted_root.json`. Historical Rekor keys
are not embedded.

Verification is offline. It checks the certificate chain, the SAN, the
Fulcio issuer extension (`1.3.6.1.4.1.57264.1.1`), certificate validity at
the Rekor integrated time, the DSSE signature over the PAE, the signed
entry timestamp, the checkpoint, the inclusion proof, each subject digest,
and the receipt hash-chain head.

An ECDSA signature inside `.intoto.jsonl` is not accepted on its own. Verify
the bundle so the identity check cannot be skipped.

## Overrides

`--fulcio-url` and `--rekor-url` replace the public-good hosts. A network
error, HTTP 4xx/5xx, or timeout exits 1 and writes nothing. The default
timeout is 10 seconds. `AGENT_RECEIPT_SIGSTORE_TIMEOUT_MS` overrides it.

Do not point a production run at a host you do not trust. Tests in this
repo use a local mock and do not call the public Fulcio or Rekor services.
