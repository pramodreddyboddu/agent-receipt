/**
 * Self-contained HTML export of an agent-receipt Markdown file.
 * No external CSS/JS — open/share as a single .html file.
 */

import { extractEmbeddedHash } from './hash.js';

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function inlineFormat(text: string): string {
  // Order: code, bold, then leave the rest escaped already
  let s = escapeHtml(text);
  s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
  s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/\*([^*]+)\*/g, '<em>$1</em>');
  return s;
}

/**
 * Convert agent-receipt Markdown to a self-contained HTML document.
 */
export function markdownToHtml(
  markdown: string,
  opts: { title?: string; redacted?: boolean } = {},
): string {
  const title = opts.title ?? 'Agent Receipt';
  const hash = extractEmbeddedHash(markdown);
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');

  const body: string[] = [];
  let i = 0;
  let inCode = false;
  let codeLang = '';
  let codeBuf: string[] = [];
  let inUl = false;
  let inOl = false;
  let inTable = false;
  let tableBuf: string[] = [];

  const closeLists = () => {
    if (inUl) {
      body.push('</ul>');
      inUl = false;
    }
    if (inOl) {
      body.push('</ol>');
      inOl = false;
    }
  };

  const flushTable = () => {
    if (!inTable) return;
    closeLists();
    const rows = tableBuf.filter((r) => r.trim().startsWith('|'));
    tableBuf = [];
    inTable = false;
    if (!rows.length) return;
    const parseRow = (row: string) =>
      row
        .trim()
        .replace(/^\|/, '')
        .replace(/\|$/, '')
        .split('|')
        .map((c) => c.trim());
    const isSep = (cells: string[]) => cells.every((c) => /^:?-+:?$/.test(c));
    body.push('<table>');
    let headerDone = false;
    for (const row of rows) {
      const cells = parseRow(row);
      if (isSep(cells)) continue;
      if (!headerDone) {
        body.push('<thead><tr>');
        for (const c of cells) body.push(`<th>${inlineFormat(c)}</th>`);
        body.push('</tr></thead><tbody>');
        headerDone = true;
      } else {
        body.push('<tr>');
        for (const c of cells) body.push(`<td>${inlineFormat(c)}</td>`);
        body.push('</tr>');
      }
    }
    body.push('</tbody></table>');
  };

  while (i < lines.length) {
    const line = lines[i];

    if (line.startsWith('```')) {
      flushTable();
      closeLists();
      if (!inCode) {
        inCode = true;
        codeLang = line.slice(3).trim();
        codeBuf = [];
      } else {
        const cls = codeLang ? ` class="language-${escapeHtml(codeLang)}"` : '';
        body.push(`<pre><code${cls}>${escapeHtml(codeBuf.join('\n'))}</code></pre>`);
        inCode = false;
        codeLang = '';
        codeBuf = [];
      }
      i++;
      continue;
    }
    if (inCode) {
      codeBuf.push(line);
      i++;
      continue;
    }

    if (line.trim().startsWith('|')) {
      closeLists();
      inTable = true;
      tableBuf.push(line);
      i++;
      continue;
    }
    if (inTable) flushTable();

    if (/^#\s+/.test(line)) {
      closeLists();
      body.push(`<h1>${inlineFormat(line.replace(/^#\s+/, ''))}</h1>`);
      i++;
      continue;
    }
    if (/^##\s+/.test(line)) {
      closeLists();
      body.push(`<h2>${inlineFormat(line.replace(/^##\s+/, ''))}</h2>`);
      i++;
      continue;
    }
    if (/^###\s+/.test(line)) {
      closeLists();
      body.push(`<h3>${inlineFormat(line.replace(/^###\s+/, ''))}</h3>`);
      i++;
      continue;
    }

    if (/^>\s?/.test(line)) {
      closeLists();
      const quoteLines: string[] = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) {
        quoteLines.push(lines[i].replace(/^>\s?/, ''));
        i++;
      }
      body.push(`<blockquote>${quoteLines.map((l) => inlineFormat(l) || '<br>').join('<br>\n')}</blockquote>`);
      continue;
    }

    if (/^[-*]\s+/.test(line)) {
      if (inOl) {
        body.push('</ol>');
        inOl = false;
      }
      if (!inUl) {
        body.push('<ul>');
        inUl = true;
      }
      body.push(`<li>${inlineFormat(line.replace(/^[-*]\s+/, ''))}</li>`);
      i++;
      continue;
    }

    if (/^\d+\.\s+/.test(line)) {
      if (inUl) {
        body.push('</ul>');
        inUl = false;
      }
      if (!inOl) {
        body.push('<ol>');
        inOl = true;
      }
      body.push(`<li>${inlineFormat(line.replace(/^\d+\.\s+/, ''))}</li>`);
      i++;
      continue;
    }

    if (line.trim() === '') {
      closeLists();
      i++;
      continue;
    }

    // Skip HTML comment hash marker visually but keep a note
    if (line.includes('agent-receipt-sha256')) {
      closeLists();
      i++;
      continue;
    }

    closeLists();
    body.push(`<p>${inlineFormat(line)}</p>`);
    i++;
  }
  flushTable();
  closeLists();
  if (inCode) {
    body.push(`<pre><code>${escapeHtml(codeBuf.join('\n'))}</code></pre>`);
  }

  const banner =
    opts.redacted || /Redacted/.test(markdown)
      ? '<div class="banner redact">Redacted export — high/secret findings masked for safer sharing</div>'
      : '';

  const integrity = hash
    ? `<footer class="integrity">Integrity SHA-256: <code>${escapeHtml(hash)}</code></footer>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  :root {
    --bg: #0f1419;
    --fg: #e7ecf1;
    --muted: #8b9aab;
    --card: #1a222c;
    --accent: #3d9cf0;
    --ok: #3ecf8e;
    --warn: #f0b429;
    --bad: #f07178;
    --border: #2a3542;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--fg);
    line-height: 1.55;
    padding: 1.5rem;
  }
  main {
    max-width: 920px;
    margin: 0 auto;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.5rem 1.75rem 2rem;
  }
  h1, h2, h3 { line-height: 1.25; }
  h1 { font-size: 1.6rem; margin-top: 0; }
  h2 {
    font-size: 1.15rem;
    margin-top: 1.75rem;
    padding-bottom: 0.35rem;
    border-bottom: 1px solid var(--border);
  }
  h3 { font-size: 1rem; color: var(--accent); }
  a { color: var(--accent); }
  code {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.9em;
    background: #0c1015;
    padding: 0.1em 0.35em;
    border-radius: 4px;
  }
  pre {
    background: #0c1015;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.85rem 1rem;
    overflow-x: auto;
  }
  pre code { background: none; padding: 0; }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.92rem;
    margin: 0.75rem 0 1rem;
  }
  th, td {
    border: 1px solid var(--border);
    padding: 0.4rem 0.55rem;
    text-align: left;
    vertical-align: top;
  }
  th { background: #121820; color: var(--muted); font-weight: 600; }
  blockquote {
    margin: 0.75rem 0 1rem;
    padding: 0.65rem 1rem;
    border-left: 4px solid var(--accent);
    background: #121820;
    color: var(--fg);
    border-radius: 0 8px 8px 0;
  }
  ul, ol { padding-left: 1.35rem; }
  li { margin: 0.25rem 0; }
  .banner {
    margin-bottom: 1rem;
    padding: 0.65rem 0.9rem;
    border-radius: 8px;
    background: #1e2a22;
    border: 1px solid #2f4a38;
    color: var(--ok);
    font-size: 0.92rem;
  }
  .banner.redact {
    background: #2a2416;
    border-color: #5a4a20;
    color: var(--warn);
  }
  footer.integrity {
    margin-top: 2rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
    color: var(--muted);
    font-size: 0.85rem;
  }
  .meta {
    color: var(--muted);
    font-size: 0.85rem;
    margin-bottom: 1rem;
  }
</style>
</head>
<body>
<main>
${banner}
<p class="meta">Generated by agent-receipt · open/share this single HTML file</p>
${body.join('\n')}
${integrity}
</main>
</body>
</html>
`;
}
