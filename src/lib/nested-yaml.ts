/**
 * Nested YAML subset for policy packs and the policy keys in
 * `.agent-receipt.yml`. No runtime dependency.
 *
 * Accepted:
 * - maps and lists, indented with spaces
 * - scalars: strings, true/false, null/~, integers
 * - flow lists `[a, b]`
 * - block scalars `|` and `>`
 * - comments (`#`) outside quotes
 *
 * Rejected: tabs, duplicate keys, flow maps, and a list item whose
 * dash is not inside a list. A colon starts a nested key only when
 * it is followed by a space or ends the token (`id: value`, `id:`).
 * `builtin:baseline` stays one string.
 */

export class NestedYamlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NestedYamlError';
  }
}

interface Frame {
  indent: number;
  type: 'map' | 'seq';
  value: Record<string, unknown> | unknown[];
}

function stripComment(line: string): string {
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === '\\' && quote === '"') {
        i++;
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === '#') return line.slice(0, i);
  }
  return line;
}

function splitFlow(input: string): string[] {
  const parts: string[] = [];
  let quote: '"' | "'" | null = null;
  let current = '';
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (quote) {
      current += ch;
      if (ch === '\\' && quote === '"') {
        if (i + 1 < input.length) current += input[++i];
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === ',') {
      parts.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}

function parseScalar(raw: string): unknown {
  const v = raw.trim();
  if (!v) return '';
  if (v.startsWith('{') || v.startsWith('}')) {
    throw new NestedYamlError('flow maps are not supported');
  }
  if (
    (v.startsWith('"') && v.endsWith('"') && v.length >= 2) ||
    (v.startsWith("'") && v.endsWith("'") && v.length >= 2)
  ) {
    const inner = v.slice(1, -1);
    if (v.startsWith('"')) {
      return inner.replace(/\\n/g, '\n').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    }
    return inner.replace(/''/g, "'");
  }
  if (v === 'true') return true;
  if (v === 'false') return false;
  if (v === 'null' || v === '~') return null;
  if (/^-?\d+$/.test(v)) return parseInt(v, 10);
  if (v.startsWith('[') && v.endsWith(']')) {
    const inner = v.slice(1, -1).trim();
    if (!inner) return [];
    return splitFlow(inner).map((part) => parseScalar(part));
  }
  return v;
}

interface ContentLine {
  indent: number;
  text: string;
  lineNo: number;
}

function peekContent(lines: string[], index: number): ContentLine | null {
  for (let i = index; i < lines.length; i++) {
    const stripped = stripComment(lines[i].replace(/\r$/, ''));
    if (!stripped.trim()) continue;
    if (stripped.trim() === '---') continue;
    const text = stripped.trim();
    const indent = stripped.match(/^ */)?.[0].length ?? 0;
    return { indent, text, lineNo: i + 1 };
  }
  return null;
}

function mappingKey(text: string): { key: string; rest: string } | null {
  const m = text.match(/^([A-Za-z0-9_-]+):(.*)$/);
  if (!m) return null;
  const rest = m[2];
  if (rest === '' || /^\s/.test(rest)) return { key: m[1], rest: rest.trim() };
  return null;
}

export function parseNestedYaml(text: string): unknown {
  if (text.includes('\t')) {
    throw new NestedYamlError('tabs are not allowed');
  }
  const lines = text.split('\n');
  const root: Record<string, unknown> = {};
  const stack: Frame[] = [{ indent: -1, type: 'map', value: root }];

  const top = (): Frame => stack[stack.length - 1];

  const popTo = (indent: number): void => {
    while (stack.length > 1 && indent < top().indent) stack.pop();
  };

  const assign = (key: string, value: unknown, lineNo: number): void => {
    const frame = top();
    if (frame.type !== 'map' || Array.isArray(frame.value)) {
      throw new NestedYamlError(`cannot set "${key}" outside a map (line ${lineNo})`);
    }
    if (Object.prototype.hasOwnProperty.call(frame.value, key)) {
      throw new NestedYamlError(`duplicate key "${key}" (line ${lineNo})`);
    }
    frame.value[key] = value;
  };

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i].replace(/\r$/, '');
    const stripped = stripComment(raw);
    if (!stripped.trim() || stripped.trim() === '---') continue;
    const indent = stripped.match(/^ */)?.[0].length ?? 0;
    const text = stripped.trim();
    const lineNo = i + 1;
    popTo(indent);

    if (text.startsWith('- ')) {
      const frame = top();
      if (frame.type !== 'seq' || !Array.isArray(frame.value)) {
        throw new NestedYamlError(`list item is not inside a list (line ${lineNo})`);
      }
      const itemText = text.slice(2).trim();
      const key = mappingKey(itemText);
      if (!key) {
        frame.value.push(parseScalar(itemText));
        continue;
      }
      const item: Record<string, unknown> = {};
      frame.value.push(item);
      stack.push({ indent: indent + 2, type: 'map', value: item });
      if (key.rest === '' || key.rest === '|' || key.rest === '>') {
        const next = peekContent(lines, i + 1);
        if (next && next.indent > indent + 2 && !next.text.startsWith('- ')) {
          const nested: Record<string, unknown> = {};
          item[key.key] = nested;
          stack.push({ indent: next.indent, type: 'map', value: nested });
          continue;
        }
        if (next && next.indent > indent + 2 && next.text.startsWith('- ')) {
          const seq: unknown[] = [];
          item[key.key] = seq;
          stack.push({ indent: next.indent, type: 'seq', value: seq });
          continue;
        }
      }
      if (key.rest === '|' || key.rest === '>') {
        const block: string[] = [];
        let j = i + 1;
        while (j < lines.length) {
          const nextRaw = stripComment(lines[j].replace(/\r$/, ''));
          if (!nextRaw.trim()) {
            block.push('');
            j++;
            continue;
          }
          const nextIndent = nextRaw.match(/^ */)?.[0].length ?? 0;
          if (nextIndent <= indent + 2) break;
          block.push(nextRaw.slice(indent + 4));
          j++;
        }
        i = j - 1;
        const joined = key.rest === '>' ? block.join(' ').trim() : block.join('\n').replace(/\s+$/, '');
        item[key.key] = joined;
        continue;
      }
      item[key.key] = parseScalar(key.rest);
      continue;
    }

    const key = mappingKey(text);
    if (!key) {
      throw new NestedYamlError(`expected a key (line ${lineNo})`);
    }
    if (key.rest === '|' || key.rest === '>') {
      const block: string[] = [];
      let j = i + 1;
      while (j < lines.length) {
        const nextRaw = stripComment(lines[j].replace(/\r$/, ''));
        if (!nextRaw.trim()) {
          block.push('');
          j++;
          continue;
        }
        const nextIndent = nextRaw.match(/^ */)?.[0].length ?? 0;
        if (nextIndent <= indent) break;
        block.push(nextRaw.slice(indent + 2));
        j++;
      }
      i = j - 1;
      const joined = key.rest === '>' ? block.join(' ').trim() : block.join('\n').replace(/\s+$/, '');
      assign(key.key, joined, lineNo);
      continue;
    }
    if (key.rest !== '') {
      assign(key.key, parseScalar(key.rest), lineNo);
      continue;
    }
    const next = peekContent(lines, i + 1);
    if (!next || next.indent <= indent) {
      assign(key.key, '', lineNo);
      continue;
    }
    if (next.text.startsWith('- ')) {
      const seq: unknown[] = [];
      assign(key.key, seq, lineNo);
      stack.push({ indent: next.indent, type: 'seq', value: seq });
      continue;
    }
    const nested: Record<string, unknown> = {};
    assign(key.key, nested, lineNo);
    stack.push({ indent: next.indent, type: 'map', value: nested });
  }

  return root;
}
