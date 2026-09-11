# Agent Receipt

> **TL;DR** demo · 2026-09-11T19:52:00.000Z · main @ b232a251f710 · 2 files · +3/−0 · risk none
>
> example session for docs

## What to review

_Nothing flagged. Skim the file list if this session should have been a no-op._

## Summary

| Metric | Value |
|--------|-------|
| Files | 2 (1M 1A) |
| Lines | +3 / −0 |
| Commits | 1 |
| Risk | none |

## Session

- **Version**: 1.0.0
- **Timestamp**: 2026-09-11T19:52:00.000Z
- **Branch**: `main`
- **HEAD**: `b232a251f710a340884d7a9c0b5ffc09f51f6c64`
- **Range**: `HEAD~1..HEAD` (`013d97b57c6e` → HEAD)
- **Agent**: demo
- **Message**: example session for docs
- **Workspace**: `/path/to/your/repo`

## Commits

- b232a25 agent: add demo changes

## Files changed

| Status | File | + | − | Binary |
|--------|------|---|---|--------|
| M | `README.md` | 2 | 0 |  |
| A | `src.ts` | 1 | 0 |  |

**Totals**: 2 files, +3 / −0

## Diff stat

```
README.md    | M    2    0 ++
src.ts       | A    1    0 +
2 files changed, 3 insertions(+), 0 deletions(-)
```

## Risk findings

_None detected._

## Diff summaries

### `README.md`

```diff
diff --git a/README.md b/README.md
index fc72a5c..e343d90 100644
--- a/README.md
+++ b/README.md
@@ -1 +1,3 @@
 # demo
+
+hello agent-receipt
```

### `src.ts`

```diff
diff --git a/src.ts b/src.ts
new file mode 100644
index 0000000..09b76aa
--- /dev/null
+++ b/src.ts
@@ -0,0 +1 @@
+export const x = 1
```

## Integrity

<!-- agent-receipt-sha256:19d6f34e9b5b494af621d3507470b39d4964b437e236df9140e0eaae34823a5d -->

SHA-256 of canonical body: `19d6f34e9b5b494af621d3507470b39d4964b437e236df9140e0eaae34823a5d`
