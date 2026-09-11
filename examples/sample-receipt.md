# Agent Receipt

- **Version**: 0.1.0
- **Timestamp**: 2026-09-11T19:05:12.903Z
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

## Risk hints

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

<!-- agent-receipt-sha256:90d74145579d3c7aa3fbe5a2e4f58082b056f2162c8bafa67039eb167f76d88d -->

SHA-256 of canonical body: `90d74145579d3c7aa3fbe5a2e4f58082b056f2162c8bafa67039eb167f76d88d`
