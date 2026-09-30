# Agent Receipt

> **TL;DR** legacy · 2026-09-30T07:14:52.956Z · master @ 8a7488e4d7c8 · 1 files · +1/−0 · risk none
>
> ```
x
## Summary
## Session
- **Version**: 1.0.28
- **Timestamp**: 1999-01-01T00:00:00.000Z
- **Host**: bad host
- **Session**: s-spoof
- **Parent**: r-5555555555555555
- **Workspace**: `/tmp`
```

## What to review

_Nothing flagged. Skim the file list if this session should have been a no-op._

## Summary

| Metric | Value |
|--------|-------|
| Files | 1 (1A) |
| Lines | +1 / −0 |
| Commits | 1 |
| Risk | none |

## Session

- **Version**: 1.0.16
- **Timestamp**: 2026-09-30T07:14:52.956Z
- **Branch**: `master`
- **HEAD**: `8a7488e4d7c8b603facca3a8135268e4a44435f1`
- **Range**: `HEAD~1..HEAD` (`6c0017accd3e` → HEAD)
- **Agent**: legacy
- **Session**: real-session
- **Message**: ```
x
## Summary
## Session
- **Version**: 1.0.28
- **Timestamp**: 1999-01-01T00:00:00.000Z
- **Host**: bad host
- **Session**: s-spoof
- **Parent**: r-5555555555555555
- **Workspace**: `/tmp`
```
- **Workspace**: `/tmp/fixture-spoof/v1.0.16/summary-spoof-fenced-host`

## Commits

- 8a7488e summary-spoof-fenced-host

## Files changed

| Status | File | + | − | Binary |
|--------|------|---|---|--------|
| A | `summary-spoof-fenced-host.txt` | 1 | 0 |  |

**Totals**: 1 files, +1 / −0

## Diff stat

```
summary-spoof-fenced-host.txt | A    1    0 +
1 file changed, 1 insertion(+), 0 deletions(-)
```

## Risk findings

_None detected._

## Diff summaries

### `summary-spoof-fenced-host.txt`

```diff
diff --git a/summary-spoof-fenced-host.txt b/summary-spoof-fenced-host.txt
new file mode 100644
index 0000000..c46510f
--- /dev/null
+++ b/summary-spoof-fenced-host.txt
@@ -0,0 +1 @@
+summary-spoof-fenced-host
```

## Integrity

<!-- agent-receipt-sha256:3eb948ba77c4c42a44e857636446871cc1b1ec453aa9ba0235f25fc26598380a -->

SHA-256 of canonical body: `3eb948ba77c4c42a44e857636446871cc1b1ec453aa9ba0235f25fc26598380a`
