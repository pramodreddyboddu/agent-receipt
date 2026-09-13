/**
 * Redaction helpers for safer sharing of receipts.
 * Masks high-signal secrets in Markdown/HTML bodies, then callers re-hash.
 */

/** True for receipt / index artifacts that may embed prior secrets. */
export function isReceiptArtifactPath(path: string): boolean {
  const n = path.replace(/\\/g, '/');
  if (/(^|\/)\.agent-receipt\//i.test(n)) return true;
  if (/(^|\/)receipt-\d{4}-\d{2}-\d{2}T[^/]*\.md$/i.test(n)) return true;
  return false;
}

/** Patterns that look like live secrets in diffs / risk detail. */
const SECRET_VALUE_PATTERNS: Array<{ re: RegExp; replacement: string }> = [
  {
    re: /\bAKIA[0-9A-Z]{16}\b/g,
    replacement: 'AKIA[REDACTED]',
  },
  {
    re: /\bghp_[A-Za-z0-9]{36}\b/g,
    replacement: 'ghp_[REDACTED]',
  },
  {
    re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
    replacement: 'github_pat_[REDACTED]',
  },
  {
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g,
    replacement: 'xox[REDACTED]',
  },
  {
    re: /-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----/g,
    replacement: '-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----',
  },
  {
    // AWS secret assignments: keep key name, mask value
    re: /(aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["']?)([A-Za-z0-9/+=]{20,})/gi,
    replacement: '$1[REDACTED]',
  },
  {
    // Connection / credential URLs: scheme://user:password@host (or :password@)
    re: /\b([a-z][a-z0-9+.-]*:\/\/(?:[^:@\/\s"'<>]*):)([^@\/\s"'<>]+)(@)/gi,
    replacement: '$1[REDACTED]$3',
  },
  {
    // Common DB / URI env assignments (full value — covers uncommon schemes)
    re: /((?:DATABASE[_-]?URL|DB[_-]?URL|MONGO(?:DB)?[_-]?(?:URI|URL)|REDIS[_-]?URL|MYSQL[_-]?URL|POSTGRES(?:QL)?[_-]?URL|CONNECTION[_-]?STRING|DATABASE[_-]?URI)\s*[:=]\s*["']?)([^\s"']+)/gi,
    replacement: '$1[REDACTED]',
  },
  {
    // password= / token= / secret= query or form params
    re: /([?&](?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token)=)([^&\s"']+)/gi,
    replacement: '$1[REDACTED]',
  },
  {
    // Generic high-entropy token assignments common in .env diffs
    re: /((?:API[_-]?KEY|SECRET[_-]?KEY|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN|PASSWORD|PRIVATE[_-]?KEY)\s*[:=]\s*["']?)([^\s"'\\]{8,})/gi,
    replacement: '$1[REDACTED]',
  },
  {
    // Truncated high-entropy previews from prior risk findings (e.g. "K8vQm2nXp9Lr…")
    re: /\b([A-Za-z0-9+/=_\-.]{8,})…/g,
    replacement: '[REDACTED]…',
  },
];

/** Risk codes whose detail rows should be fully masked in findings tables. */
const HIGH_SECRET_CODES = new Set([
  'aws-access-key',
  'aws-secret-key',
  'private-key-block',
  'github-token',
  'slack-token',
  'high-entropy-secret',
  'env-file',
  'secret-looking-path',
]);

export function redactSecretsInText(text: string): string {
  let out = text;
  for (const { re, replacement } of SECRET_VALUE_PATTERNS) {
    out = out.replace(re, replacement);
  }
  return out;
}

/**
 * Redact a full Markdown receipt body (before Integrity).
 * - Masks secret values in diffs and prose
 * - Masks high/secret risk detail cells
 * - Omits nested prior-receipt / index diff bodies (avoids re-embedding secrets)
 * - Inserts a redaction notice under Session when not already present
 */
export function redactMarkdownBody(markdown: string): string {
  const normalized = markdown.replace(/\r\n/g, '\n');
  const lines = normalized.split('\n');
  const out: string[] = [];
  let inDiffFence = false;
  let inNestedArtifactDiff = false;
  let nestedOmitted = false;
  let inRiskTable = false;
  let sawRedactionNotice = false;
  let currentDiffPath: string | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.startsWith('## Integrity') || line.includes('agent-receipt-sha256')) {
      break;
    }

    if (line.includes('**Redacted**:') || line.includes('Snapshot is redacted')) {
      sawRedactionNotice = true;
    }

    // Track ### `path` under Diff summaries
    const pathHeader = line.match(/^###\s+`([^`]+)`\s*$/);
    if (pathHeader) {
      currentDiffPath = pathHeader[1];
      out.push(line);
      continue;
    }

    if (line.startsWith('## Risk findings')) {
      inRiskTable = true;
      out.push(line);
      continue;
    }
    if (inRiskTable && line.startsWith('## ')) {
      inRiskTable = false;
    }

    if (line.trim() === '```diff' || line.trim() === '```') {
      if (line.trim() === '```diff') {
        inDiffFence = true;
        inNestedArtifactDiff = Boolean(
          currentDiffPath && isReceiptArtifactPath(currentDiffPath),
        );
        nestedOmitted = false;
        out.push(line);
        continue;
      }
      if (inDiffFence && line.trim() === '```') {
        if (inNestedArtifactDiff && !nestedOmitted) {
          out.push('+[REDACTED — nested receipt/index body omitted]');
        }
        inDiffFence = false;
        inNestedArtifactDiff = false;
        nestedOmitted = false;
        out.push(line);
        continue;
      }
      out.push(line);
      continue;
    }

    if (inDiffFence) {
      if (inNestedArtifactDiff) {
        if (!nestedOmitted) {
          out.push('+[REDACTED — nested receipt/index body omitted]');
          nestedOmitted = true;
        }
        continue;
      }
      out.push(redactSecretsInText(line));
      continue;
    }

    if (inRiskTable && line.startsWith('|')) {
      // | sev | `code` | detail |
      const cells = splitTableRow(line);
      if (cells.length >= 3 && cells[0] !== 'Sev' && !/^-+$/.test(cells[0])) {
        const sev = cells[0].trim().toLowerCase();
        const codeCell = cells[1].trim();
        const codeMatch = codeCell.match(/`([^`]+)`/);
        const code = codeMatch?.[1] ?? codeCell;
        const isSecret = sev === 'high' || HIGH_SECRET_CODES.has(code);
        if (isSecret) {
          const detail = redactSecretsInText(cells.slice(2).join('|')).replace(
            /[A-Za-z0-9/+=_-]{16,}/g,
            '[REDACTED]',
          );
          out.push(
            `| ${cells[0].trim()} | ${cells[1].trim()} | ${detail.includes('[REDACTED]') ? detail : '[REDACTED — secret detail masked]'} |`,
          );
          continue;
        }
      }
      out.push(redactSecretsInText(line));
      continue;
    }

    // What to review lines for high secrets
    if (/^\d+\.\s+\*\*high\*\*/.test(line)) {
      out.push(redactSecretsInText(line).replace(/—\s+.+$/, '— [REDACTED — secret detail masked]'));
      continue;
    }

    out.push(redactSecretsInText(line));
  }

  // Drop trailing blanks, then inject redaction notice after Session block if needed
  while (out.length > 0 && out[out.length - 1].trim() === '') out.pop();

  if (!sawRedactionNotice) {
    const sessionIdx = out.findIndex((l) => l === '## Session');
    if (sessionIdx >= 0) {
      // Find end of Session section (next ## or end)
      let insertAt = sessionIdx + 1;
      while (insertAt < out.length && !out[insertAt].startsWith('## ')) {
        insertAt++;
      }
      // Insert before the blank line preceding next section if present
      let at = insertAt;
      if (at > 0 && out[at - 1].trim() === '') at = at - 1;
      out.splice(at, 0, '- **Redacted**: yes — high/secret findings masked for safer sharing');
    } else {
      out.unshift(
        '> **Redacted** — high/secret findings masked for safer sharing',
        '',
      );
    }
  }

  return out.join('\n') + '\n';
}

function splitTableRow(line: string): string[] {
  const trimmed = line.trim().replace(/^\|/, '').replace(/\|$/, '');
  return trimmed.split('|').map((c) => c.trim());
}

/**
 * Apply redaction to a full receipt (with or without Integrity) and return
 * body ready for appendHashFooter.
 */
export function prepareRedactedBody(markdown: string): string {
  return redactMarkdownBody(markdown);
}
