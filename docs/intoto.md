# in-toto / SLSA attestation

`agent-receipt attest` writes an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) inside a [DSSE](https://github.com/secure-systems-lab/dsse) envelope. The file is `.intoto.jsonl`: one envelope per line, so common in-toto and Sigstore tools can read it.

```bash
agent-receipt keygen
agent-receipt trust add --self
agent-receipt attest
agent-receipt attest --verify .agent-receipt/receipts/receipt-….intoto.jsonl
agent-receipt attest --slsa
agent-receipt export --format intoto
```

## Envelope

| Field | Value |
| --- | --- |
| `payloadType` | `application/vnd.in-toto+json` |
| `payload` | Standard base64 of the statement JSON |
| `signatures[].keyid` | Fingerprint of the local Ed25519 key (same value `sign` writes) |
| `signatures[].sig` | Base64 of the raw 64-byte Ed25519 signature over the DSSE PAE |
| `signatures[].publicKey` | SPKI PEM. Extra field. DSSE consumers ignore it. Peers need it because the trust store lists fingerprints only |

The private key never enters the file. Missing keys, or `--no-sign`, write `"signatures": []`, print a warning, and exit 0. `attest --verify` of that file exits 2.

`attest --keyless` writes the same statement and also a Sigstore bundle, `<stem>.sigstore.json`. That signature is ECDSA P-256 over the same PAE. Verify the bundle, not the ECDSA bytes inside the jsonl. See [keyless.md](keyless.md).

The PAE is `DSSEv1 <len(type)> <type> <len(body)> <body>` per DSSE spec 1.0.2. Lengths are ASCII decimal byte counts with no leading zeros.

## Statement

`_type` is `https://in-toto.io/Statement/v1`.

Subjects:

- The receipt file, named relative to the working directory. Digest is sha256 of the raw file bytes.
- Each changed file that is still a regular file inside the working directory and under the byte cap. The same raw-byte digest.

The hash-chain head is the receipt canonical sha256 (the hex `verify` prints). It is not the raw file digest. `attest --verify` checks both.

Default predicate type: `https://agent-receipt.dev/run/v1`. It carries agent, session, commands, tool calls, policy hits, exit code, `hashChainHead`, and `receipt.name`. Host and workspace are omitted.

`--slsa` or `--predicate slsa` uses `https://slsa.dev/provenance/v1`. The same facts sit in `buildDefinition.externalParameters`. `buildDefinition.buildType` is the run predicate URI. `runDetails.builder.id` is `https://agent-receipt.dev/builder/v1`. A byproduct named `hash-chain-head` repeats the canonical sha256.

Narrative fields are redacted before they are copied. There is no `--no-redact` on `attest`. Redacted output still verifies, because the subject digest is the original receipt file.

## Verify

`attest --verify` fails closed:

| Exit | When |
| --- | --- |
| 0 | Every envelope: signature ok, every subject digest matches the file, hash-chain head matches the receipt |
| 2 | Unsigned, bad signature, untrusted fingerprint when the allowlist is active, digest mismatch, hash mismatch, or a receipt that fails integrity |
| 1 | Missing file, not a regular file, empty, a UTF-8 BOM, over the size cap, or a line that is not JSON |

An empty trust store accepts any cryptographically valid signature and sets `trusted` to null. Add the fingerprint with `agent-receipt trust add --self` or `--trusted-key`. This is not a certificate authority.

`attest` does not append `audit.jsonl`. Subject digests are the files on disk at attest time. A later edit of a subject fails verify.

A session package (`attest path/to/id.session`) writes one envelope per packaged receipt, in `<id>.intoto.jsonl` beside the package. `--session <id>` does the same for local receipts and writes beside `outDir`.

Schema: [`intoto-statement.schema.json`](intoto-statement.schema.json).
