# Agent Receipt

> **TL;DR** legacy · 2026-09-30T07:14:56.636Z · master @ 6a0ab57ca8be · 1 files · +1/−0 · risk none
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

- **Version**: 1.0.27
- **Timestamp**: 2026-09-30T07:14:56.636Z
- **Branch**: `master`
- **HEAD**: `6a0ab57ca8be2aad627a4efccaacaa67d12836b2`
- **Range**: `HEAD~1..HEAD` (`ab207d2600c6` → HEAD)
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
- **Workspace**: `/tmp/fixture-spoof/v1.0.27/summary-spoof-fenced-host`

## Commits

- 6a0ab57 summary-spoof-fenced-host

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

<!-- agent-receipt-sha256:f1dcf02a44d048e10c576d9c6e3f3eea8d2ce23e7de4e63bf90b6a045f8cef52 -->

SHA-256 of canonical body: `f1dcf02a44d048e10c576d9c6e3f3eea8d2ce23e7de4e63bf90b6a045f8cef52`
