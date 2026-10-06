/**
 * Local read-only viewer for receipts and linked session trees.
 * Receipt ids are an in-memory alias map. Nothing here takes a filesystem
 * path from the request URL. Display text is redacted before it is served
 * or written. Host labels stay (maskHost: false) and then go through the
 * same secret masks as share and report.
 */
import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';
import { readAuditRawLines, verifyAuditChain } from './audit.js';
import { escapeHtml } from './html.js';
import {
  isReceiptDocument,
  listOutDirReceipts,
  parseLinkMeta,
  readLocalReceipt,
} from './link.js';
import { failedOnFromIndex, findIndexEntry } from './receipt-index.js';
import { isProveOnePagerName, isSessionPackageDirName, isSharePackageDirName } from './receipt.js';
import { redactMarkdownBody, redactSecretsInText } from './redact.js';
import { parseRiskSummaryMarkdown } from './risk.js';
import { inspectReceiptSignature, type SignatureStatus } from './sign.js';
import { applyTrust, loadTrustedFingerprints } from './trust.js';
import { reportVerify } from '../commands/verify.js';

const MAX_RECEIPT_BYTES = 8 * 1024 * 1024;
const MAX_SIDE_BYTES = 2 * 1024 * 1024;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$/;

export interface ViewerBuildOptions {
  cwd: string;
  receiptsDir?: string;
  trustedKeys?: string[];
  requireSig?: boolean;
}

export interface ViewerVerify {
  status: 'OK' | 'FAILED';
  reason: string;
}

export interface ViewerPolicyHit {
  action: string;
  severity: string;
  rule: string;
  evidence: string;
  pack: null;
}

export interface ViewerFile {
  status: string;
  path: string;
  insertions: number;
  deletions: number;
}

export interface ViewerToolCall {
  tool: string;
  exit: number | null;
  command: string | null;
  files: string[];
}

export interface ViewerSignature {
  present: boolean;
  ok: boolean | null;
  alg: string | null;
  fingerprint: string | null;
  trusted: boolean | null;
  reason: string | null;
}

export interface ViewerKeyless {
  present: boolean;
  mediaType: string | null;
}

export interface ViewerAttestation {
  present: boolean;
  signed: boolean | null;
  predicateType: string | null;
}

export interface ViewerHashChain {
  position: number | null;
  events: number;
  chainOk: boolean | null;
  matched: boolean;
}

export interface ViewerGate {
  exitCode: 0 | 2;
  failed: boolean;
  risk: string;
  failedOn: boolean;
}

export interface ViewerReceipt {
  id: string;
  timestamp: string | null;
  agent: string | null;
  adapter: string | null;
  risk: string;
  exitCode: 0 | 2;
  failed: boolean;
  signed: boolean;
  verify: ViewerVerify;
  policyHits: ViewerPolicyHit[];
  session: string | null;
  host: string | null;
  parent: string | null;
  message: string | null;
  commands: string[];
  files: ViewerFile[];
  toolCalls: ViewerToolCall[];
  gate: ViewerGate;
  signature: ViewerSignature;
  keyless: ViewerKeyless;
  attestation: ViewerAttestation;
  hashChain: ViewerHashChain;
  sha256: string;
}

export interface ViewerSessionNode {
  id: string;
  parent: string | null;
  agent: string | null;
  host: string | null;
  timestamp: string | null;
  verify: 'OK' | 'FAILED';
  children: ViewerSessionNode[];
}

export interface ViewerSession {
  id: string;
  hosts: string[];
  roots: ViewerSessionNode[];
}

export interface ViewerSnapshot {
  receipts: ViewerReceipt[];
  sessions: ViewerSession[];
}

export interface ViewerCatalog {
  snapshot: ViewerSnapshot;
  byId: Map<string, ViewerReceipt>;
}

export interface ViewerListItem {
  id: string;
  timestamp: string | null;
  agent: string | null;
  adapter: string | null;
  risk: string;
  exitCode: 0 | 2;
  failed: boolean;
  signed: boolean;
  verify: ViewerVerify;
  policyHits: ViewerPolicyHit[];
  session: string | null;
  host: string | null;
  parent: string | null;
  message: string | null;
}

const STYLE = [
  ':root { color-scheme: light dark; }',
  'body { margin: 1.5rem; font: 15px/1.45 sans-serif; }',
  'h1 { font-size: 1.25rem; margin: 0 0 0.5rem; }',
  'form { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: end; margin: 0 0 1rem; }',
  'label { display: flex; flex-direction: column; gap: 0.2rem; font-size: 0.85rem; }',
  'table { border-collapse: collapse; width: 100%; }',
  'th, td { text-align: left; padding: 0.35rem 0.5rem; border-bottom: 1px solid #8884; vertical-align: top; }',
  'tbody tr { cursor: pointer; }',
  '#detail, #sessions { margin-top: 1.25rem; }',
  'pre { white-space: pre-wrap; }',
].join('\n');

const CLIENT_JS = [
  '(function () {',
  '  var embedded = document.getElementById("viewer-data");',
  '  function text(node, value) { node.textContent = value == null ? "" : String(value); }',
  '  function el(tag) { return document.createElement(tag); }',
  '  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }',
  '  function riskOf(row) { return row.risk || "none"; }',
  '  function signedOf(row) { return row.signed ? "signed" : "unsigned"; }',
  '  function policyText(row) {',
  '    var hits = row.policyHits || [];',
  '    return hits.map(function (hit) { return (hit.action || "") + " " + (hit.rule || ""); }).join(", ");',
  '  }',
  '  function matches(row) {',
  '    var q = document.getElementById("q").value.toLowerCase();',
  '    var agent = document.getElementById("agent").value;',
  '    var risk = document.getElementById("risk").value;',
  '    var signed = document.getElementById("signed").value;',
  '    var failedOnly = document.getElementById("failed").checked;',
  '    if (agent && row.agent !== agent) return false;',
  '    if (risk && riskOf(row) !== risk) return false;',
  '    if (signed === "signed" && !row.signed) return false;',
  '    if (signed === "unsigned" && row.signed) return false;',
  '    if (failedOnly && row.failed !== true) return false;',
  '    if (!q) return true;',
  '    var blob = [row.id, row.agent, row.adapter, row.message, row.host, row.session, riskOf(row), policyText(row)].join(" ").toLowerCase();',
  '    return blob.indexOf(q) !== -1;',
  '  }',
  '  function addLine(parent, label, value) {',
  '    var p = el("p");',
  '    var strong = el("strong");',
  '    text(strong, label);',
  '    p.appendChild(strong);',
  '    p.appendChild(document.createTextNode(" " + (value == null ? "" : String(value))));',
  '    parent.appendChild(p);',
  '  }',
  '  function addList(parent, title, items) {',
  '    var h = el("h3");',
  '    text(h, title);',
  '    parent.appendChild(h);',
  '    var ul = el("ul");',
  '    (items || []).forEach(function (item) {',
  '      var li = el("li");',
  '      text(li, typeof item === "string" ? item : JSON.stringify(item));',
  '      ul.appendChild(li);',
  '    });',
  '    parent.appendChild(ul);',
  '  }',
  '  function paint(box, full) {',
  '    clear(box);',
  '    var h = el("h2");',
  '    text(h, full.id || "");',
  '    box.appendChild(h);',
  '    addLine(box, "Verify", full.verify && full.verify.status);',
  '    addLine(box, "Reason", full.verify && full.verify.reason);',
  '    addLine(box, "Agent", full.agent);',
  '    addLine(box, "Host", full.host);',
  '    addLine(box, "Session", full.session);',
  '    addLine(box, "Parent", full.parent);',
  '    addLine(box, "Message", full.message);',
  '    addLine(box, "Risk", riskOf(full));',
  '    addLine(box, "Exit", full.exitCode);',
  '    addLine(box, "Signed", signedOf(full));',
  '    if (full.commands) addList(box, "Commands", full.commands);',
  '    if (full.files) addList(box, "Files", full.files.map(function (file) {',
  '      return (file.status || "") + " " + (file.path || "");',
  '    }));',
  '    if (full.toolCalls) addList(box, "Tool calls", full.toolCalls.map(function (call) {',
  '      return (call.tool || "") + " exit " + (call.exit == null ? "" : call.exit) + " " + (call.command || "");',
  '    }));',
  '    if (full.policyHits) addList(box, "Policy", full.policyHits.map(function (hit) {',
  '      return (hit.action || "") + " " + (hit.severity || "") + " " + (hit.rule || "") + " " + (hit.evidence || "");',
  '    }));',
  '    if (full.gate) addLine(box, "Gate", "exit " + full.gate.exitCode + " failed " + full.gate.failed);',
  '    if (full.signature) addLine(box, "Signature", (full.signature.present ? "present" : "absent") + " " + (full.signature.alg || "") + " " + (full.signature.fingerprint || "") + " " + (full.signature.reason || ""));',
  '    if (full.keyless) addLine(box, "Keyless", full.keyless.present ? (full.keyless.mediaType || "present") : "absent");',
  '    if (full.attestation) addLine(box, "Attestation", full.attestation.present ? ((full.attestation.signed ? "signed" : "unsigned") + " " + (full.attestation.predicateType || "")) : "absent");',
  '    if (full.hashChain) addLine(box, "Hash chain", "position " + full.hashChain.position + " events " + full.hashChain.events + " chainOk " + full.hashChain.chainOk);',
  '  }',
  '  function renderTable(receipts) {',
  '    var body = document.getElementById("rows");',
  '    clear(body);',
  '    receipts.filter(matches).forEach(function (row) {',
  '      var tr = el("tr");',
  '      tr.addEventListener("click", function () { showDetail(row); });',
  '      [row.timestamp, row.agent, row.adapter, riskOf(row), row.exitCode, signedOf(row), row.verify && row.verify.status, policyText(row)].forEach(function (value) {',
  '        var td = el("td");',
  '        text(td, value);',
  '        tr.appendChild(td);',
  '      });',
  '      body.appendChild(tr);',
  '    });',
  '  }',
  '  function showDetail(row) {',
  '    var box = document.getElementById("detail");',
  '    if (row.commands) { paint(box, row); return; }',
  '    fetch("/api/receipts/" + encodeURIComponent(row.id)).then(function (res) { return res.json(); }).then(function (body) {',
  '      paint(box, (body && body.receipt) || row);',
  '    });',
  '  }',
  '  function renderSessions(sessions) {',
  '    var box = document.getElementById("sessions");',
  '    clear(box);',
  '    (sessions || []).forEach(function (session) {',
  '      var h = el("h3");',
  '      text(h, (session.id || "") + " [" + (session.hosts || []).join(", ") + "]");',
  '      box.appendChild(h);',
  '      var ul = el("ul");',
  '      function walk(nodes) {',
  '        (nodes || []).forEach(function (node) {',
  '          var li = el("li");',
  '          text(li, (node.id || "") + " parent " + (node.parent || "") + " host " + (node.host || "") + " agent " + (node.agent || "") + " " + (node.verify || ""));',
  '          ul.appendChild(li);',
  '          if (node.children && node.children.length) walk(node.children);',
  '        });',
  '      }',
  '      walk(session.roots || []);',
  '      box.appendChild(ul);',
  '    });',
  '  }',
  '  function fillAgents(receipts) {',
  '    var sel = document.getElementById("agent");',
  '    var seen = {};',
  '    receipts.forEach(function (row) { if (row.agent) seen[row.agent] = true; });',
  '    Object.keys(seen).sort().forEach(function (name) {',
  '      var opt = el("option");',
  '      opt.value = name;',
  '      text(opt, name);',
  '      sel.appendChild(opt);',
  '    });',
  '  }',
  '  function boot(data) {',
  '    var receipts = data.receipts || [];',
  '    var sessions = data.sessions || [];',
  '    fillAgents(receipts);',
  '    renderTable(receipts);',
  '    renderSessions(sessions);',
  '    ["q", "agent", "risk", "signed", "failed"].forEach(function (id) {',
  '      document.getElementById(id).addEventListener("input", function () { renderTable(receipts); });',
  '      document.getElementById(id).addEventListener("change", function () { renderTable(receipts); });',
  '    });',
  '  }',
  '  document.addEventListener("submit", function (event) { event.preventDefault(); }, true);',
  '  if (embedded && embedded.textContent.trim()) boot(JSON.parse(embedded.textContent));',
  '  else Promise.all([',
  '    fetch("/api/receipts").then(function (res) { return res.json(); }),',
  '    fetch("/api/sessions").then(function (res) { return res.json(); })',
  '  ]).then(function (parts) { boot({ receipts: parts[0].receipts, sessions: parts[1].sessions }); });',
  '})();',
].join('\n');

function sha256Base64(value: string): string {
  return createHash('sha256').update(value).digest('base64');
}

export function viewerContentSecurityPolicy(connectSelf: boolean): string {
  return [
    "default-src 'none'",
    `script-src 'sha256-${sha256Base64(CLIENT_JS)}'`,
    `style-src 'sha256-${sha256Base64(STYLE)}'`,
    connectSelf ? "connect-src 'self'" : "connect-src 'none'",
    "img-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "object-src 'none'",
    "frame-ancestors 'none'",
  ].join('; ');
}

const API_CSP = [
  "default-src 'none'",
  "script-src 'none'",
  "style-src 'none'",
  "img-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
  "frame-ancestors 'none'",
].join('; ');

export function renderViewerPage(snapshot: ViewerSnapshot | null, connectSelf: boolean): string {
  const csp = viewerContentSecurityPolicy(connectSelf);
  const payload = snapshot ? escapeHtml(stableJson(snapshot)) : '';
  return [
    '<!DOCTYPE html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="referrer" content="no-referrer">',
    `<meta http-equiv="Content-Security-Policy" content="${csp}">`,
    '<title>agent-receipt</title>',
    `<style>${STYLE}</style>`,
    '</head>',
    '<body>',
    '<h1>agent-receipt</h1>',
    '<form id="filters">',
    '<label>Search <input id="q" type="search"></label>',
    '<label>Agent <select id="agent"><option value="">any</option></select></label>',
    '<label>Risk <select id="risk"><option value="">any</option><option>high</option><option>medium</option><option>low</option><option>none</option></select></label>',
    '<label>Signed <select id="signed"><option value="">any</option><option value="signed">signed</option><option value="unsigned">unsigned</option></select></label>',
    '<label>Failed <input id="failed" type="checkbox"></label>',
    '</form>',
    '<table>',
    '<thead><tr><th>Time</th><th>Agent</th><th>Adapter</th><th>Risk</th><th>Exit</th><th>Signed</th><th>Verify</th><th>Policy</th></tr></thead>',
    '<tbody id="rows"></tbody>',
    '</table>',
    '<h2>Session tree</h2>',
    '<div id="sessions"></div>',
    '<h2>Receipt</h2>',
    '<div id="detail"></div>',
    `<pre id="viewer-data" hidden>${payload}</pre>`,
    `<script>${CLIENT_JS}</script>`,
    '</body>',
    '</html>',
    '',
  ].join('\n');
}

export function stableJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

export function writeStaticViewer(dir: string, snapshot: ViewerSnapshot): void {
  mkdirSync(dir, { recursive: true });
  const json = stableJson(snapshot);
  writeFileSync(join(dir, 'index.html'), renderViewerPage(snapshot, false), 'utf8');
  writeFileSync(join(dir, 'data.json'), json, 'utf8');
}

function safePublicId(value: string | null | undefined): value is string {
  return typeof value === 'string' && SAFE_ID.test(value) && !value.includes('..');
}

function regularFile(filePath: string): boolean {
  try {
    const st = lstatSync(filePath);
    return st.isFile() && !st.isSymbolicLink();
  } catch {
    return false;
  }
}

function listReceiptFiles(cwd: string, receiptsDir: string | undefined): string[] {
  if (!receiptsDir) {
    return listOutDirReceipts(cwd).filter(regularFile).sort((a, b) => a.localeCompare(b));
  }
  const dir = isAbsolute(receiptsDir) ? receiptsDir : resolve(cwd, receiptsDir);
  if (!existsSync(dir)) return [];
  let st;
  try {
    st = lstatSync(dir);
  } catch {
    return [];
  }
  if (st.isSymbolicLink() || !st.isDirectory()) {
    throw new Error('--receipts must be a directory');
  }
  return readdirSync(dir)
    .filter((name) => !isSharePackageDirName(name) && !isSessionPackageDirName(name))
    .filter((name) => name.endsWith('.md') && !isProveOnePagerName(name))
    .map((name) => join(dir, name))
    .filter(regularFile)
    .sort((a, b) => a.localeCompare(b));
}

function sectionLines(markdown: string, heading: string): string[] {
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  const start = lines.findIndex((line) => line === heading);
  if (start < 0) return [];
  const out: string[] = [];
  for (let i = start + 1; i < lines.length; i++) {
    if (lines[i].startsWith('## ')) break;
    out.push(lines[i]);
  }
  return out;
}

function headerValue(markdown: string, label: string): string | null {
  const prefix = `- **${label}**:`;
  for (const line of markdown.split('\n')) {
    if (!line.startsWith(prefix)) continue;
    const value = line.slice(prefix.length).trim();
    return value ? value : null;
  }
  return null;
}

function unquote(value: string): string {
  const trimmed = value.trim();
  if (trimmed.startsWith('`') && trimmed.endsWith('`') && trimmed.length >= 2) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function parseCommands(lines: string[]): string[] {
  const commands: string[] = [];
  for (const line of lines) {
    if (!line.startsWith('- ')) continue;
    const text = line.slice(2).trim();
    if (!text || text.startsWith('_')) continue;
    commands.push(text);
  }
  return commands;
}

function parseFiles(lines: string[]): ViewerFile[] {
  const files: ViewerFile[] = [];
  for (const line of lines) {
    const match = line.match(/^\|\s*([^|]+?)\s*\|\s*`([^`]*)`\s*\|\s*(-?\d+)\s*\|\s*(-?\d+)\s*\|/);
    if (!match) continue;
    if (match[1].trim() === 'Status') continue;
    files.push({
      status: match[1].trim(),
      path: match[2],
      insertions: Number(match[3]),
      deletions: Number(match[4]),
    });
  }
  return files;
}

function parseToolCalls(lines: string[]): ViewerToolCall[] {
  const calls: ViewerToolCall[] = [];
  for (const line of lines) {
    if (!line.startsWith('- `')) continue;
    const parts = line.slice(2).split(' — ');
    const tool = unquote(parts[0] ?? '');
    if (!tool) continue;
    let exit: number | null = null;
    let command: string | null = null;
    const files: string[] = [];
    for (const part of parts.slice(1)) {
      const exitMatch = part.match(/^exit (-?\d+)$/);
      if (exitMatch) {
        exit = Number(exitMatch[1]);
        continue;
      }
      if (part.startsWith('files:')) {
        for (const found of part.matchAll(/`([^`]+)`/g)) files.push(found[1]);
        continue;
      }
      if (part.startsWith('`')) command = unquote(part);
    }
    calls.push({ tool, exit, command, files });
  }
  return calls;
}

function parsePolicyHits(lines: string[]): ViewerPolicyHit[] {
  const hits: ViewerPolicyHit[] = [];
  for (const line of lines) {
    const match = line.match(/^\|\s*(deny|warn)\s*\|\s*([A-Za-z]+)\s*\|\s*`([^`]*)`\s*\|\s*(.*?)\s*\|\s*$/i);
    if (!match) continue;
    hits.push({
      action: match[1].toLowerCase(),
      severity: match[2].toLowerCase(),
      rule: match[3],
      evidence: match[4],
      pack: null,
    });
  }
  return hits;
}

function clip(value: string | null): string | null {
  if (value == null) return null;
  const flat = value.replace(/\s+/g, ' ').trim();
  if (!flat) return '';
  return flat.length > 300 ? `${flat.slice(0, 299)}…` : flat;
}

function publicSignature(signature: SignatureStatus): ViewerSignature {
  return {
    present: signature.present,
    ok: signature.ok,
    alg: signature.alg,
    fingerprint: signature.fingerprint,
    trusted: signature.trusted,
    reason: clip(signature.reason),
  };
}

function safeToken(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  if (!value || value.length > 200) return null;
  if (/[\r\n\0]/.test(value)) return null;
  if (value.includes('PRIVATE KEY') || value.includes('BEGIN CERTIFICATE')) return null;
  return value;
}

function readCapped(filePath: string): string | null {
  try {
    const st = lstatSync(filePath);
    if (st.isSymbolicLink() || !st.isFile() || st.size > MAX_SIDE_BYTES) return null;
    return readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }
}

function attestationInfo(receiptPath: string): ViewerAttestation {
  const filePath = receiptPath.replace(/\.md$/i, '') + '.intoto.jsonl';
  if (!existsSync(filePath)) return { present: false, signed: null, predicateType: null };
  const text = readCapped(filePath);
  if (text == null) return { present: true, signed: null, predicateType: null };
  const line = text.split('\n').find((item) => item.trim());
  if (!line) return { present: true, signed: null, predicateType: null };
  try {
    const doc = JSON.parse(line) as { payload?: unknown; signatures?: unknown };
    const sigs = Array.isArray(doc.signatures) ? doc.signatures : [];
    const signed = sigs.some((sig) => {
      if (!sig || typeof sig !== 'object') return false;
      const value = (sig as { sig?: unknown }).sig;
      return typeof value === 'string' && value.length > 0;
    });
    let predicateType: string | null = null;
    if (typeof doc.payload === 'string') {
      const payload = JSON.parse(Buffer.from(doc.payload, 'base64').toString('utf8')) as {
        predicateType?: unknown;
      };
      predicateType = safeToken(payload.predicateType);
    }
    return { present: true, signed, predicateType };
  } catch {
    return { present: true, signed: null, predicateType: null };
  }
}

function keylessInfo(receiptPath: string): ViewerKeyless {
  const filePath = receiptPath.replace(/\.md$/i, '') + '.sigstore.json';
  if (!existsSync(filePath)) return { present: false, mediaType: null };
  const text = readCapped(filePath);
  if (text == null) return { present: true, mediaType: null };
  try {
    const doc = JSON.parse(text) as { mediaType?: unknown };
    return { present: true, mediaType: safeToken(doc.mediaType) };
  } catch {
    return { present: true, mediaType: null };
  }
}

function hashChainFor(cwd: string, sha256: string): ViewerHashChain {
  const chain = verifyAuditChain(cwd);
  let lines: string[] = [];
  try {
    lines = readAuditRawLines(cwd);
  } catch {
    lines = [];
  }
  let position: number | null = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].endsWith('\r') ? lines[i].slice(0, -1) : lines[i];
    try {
      const parsed = JSON.parse(line) as { sha256?: unknown };
      if (parsed && parsed.sha256 === sha256) position = i + 1;
    } catch {
      // A broken audit line is not a match. chainOk still reports the chain.
    }
  }
  return {
    position,
    events: chain.events,
    chainOk: chain.events === 0 ? null : chain.ok,
    matched: position !== null,
  };
}

function redactTree(value: unknown): unknown {
  if (typeof value === 'string') return redactSecretsInText(value);
  if (typeof value === 'number' || typeof value === 'boolean' || value == null) return value;
  if (Array.isArray(value)) return value.map((item) => redactTree(item));
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>)) {
      out[key] = redactTree((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return null;
}

function byTime(a: ViewerReceipt, b: ViewerReceipt): number {
  const time = (a.timestamp ?? '').localeCompare(b.timestamp ?? '');
  if (time !== 0) return time;
  return a.id.localeCompare(b.id);
}

function buildSessions(receipts: ViewerReceipt[]): ViewerSession[] {
  const groups = new Map<string, ViewerReceipt[]>();
  for (const receipt of receipts) {
    if (!receipt.session) continue;
    const list = groups.get(receipt.session) ?? [];
    list.push(receipt);
    groups.set(receipt.session, list);
  }
  const sessions: ViewerSession[] = [];
  for (const [id, members] of groups) {
    const sorted = [...members].sort(byTime);
    const byMember = new Map(sorted.map((receipt) => [receipt.id, receipt]));
    const children = new Map<string, ViewerReceipt[]>();
    const roots: ViewerReceipt[] = [];
    for (const receipt of sorted) {
      if (receipt.parent && receipt.parent !== receipt.id && byMember.has(receipt.parent)) {
        const list = children.get(receipt.parent) ?? [];
        list.push(receipt);
        children.set(receipt.parent, list);
      } else {
        roots.push(receipt);
      }
    }
    const placed = new Set<string>();
    const toNode = (receipt: ViewerReceipt): ViewerSessionNode => {
      placed.add(receipt.id);
      const kids = (children.get(receipt.id) ?? []).filter((child) => !placed.has(child.id)).map(toNode);
      return {
        id: receipt.id,
        parent: receipt.parent,
        agent: receipt.agent,
        host: receipt.host,
        timestamp: receipt.timestamp,
        verify: receipt.verify.status,
        children: kids,
      };
    };
    const rootNodes = roots.map(toNode);
    for (const receipt of sorted) {
      if (!placed.has(receipt.id)) rootNodes.push(toNode(receipt));
    }
    const hosts = [...new Set(sorted.map((receipt) => receipt.host).filter((host): host is string => Boolean(host)))].sort(
      (a, b) => a.localeCompare(b),
    );
    sessions.push({ id, hosts, roots: rootNodes });
  }
  sessions.sort((a, b) => a.id.localeCompare(b.id));
  return sessions;
}

function buildReceipt(
  cwd: string,
  filePath: string,
  requireSig: boolean,
  store: ReturnType<typeof loadTrustedFingerprints>,
): { receipt: ViewerReceipt; aliases: string[] } | null {
  if (!regularFile(filePath)) return null;
  let size = 0;
  try {
    size = lstatSync(filePath).size;
  } catch {
    return null;
  }
  if (size > MAX_RECEIPT_BYTES) return null;
  const ref = readLocalReceipt(filePath);
  if (!ref) return null;
  let original = '';
  try {
    original = readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }
  if (!isReceiptDocument(original)) return null;
  const id = safePublicId(ref.id) ? ref.id : safePublicId(ref.sha256) ? ref.sha256 : null;
  if (!id) return null;
  const reported = reportVerify(id, original, { quiet: true });
  let signature = inspectReceiptSignature(filePath, reported.sha256);
  if (signature.ok === true) signature = applyTrust(signature, store);
  let ok = reported.ok;
  let reason = ok ? '' : reported.reason;
  if (reason === 'OK') reason = '';
  if (ok && requireSig) {
    if (!signature.present) {
      ok = false;
      reason = 'signature required: signature absent';
    } else if (signature.ok !== true) {
      ok = false;
      reason = signature.reason || 'signature invalid';
    }
  }
  if (!ok && (reason === 'OK' || !reason)) reason = reported.reason === 'OK' ? '' : reported.reason;
  const status: 'OK' | 'FAILED' = ok ? 'OK' : 'FAILED';
  const redacted = redactMarkdownBody(original, { maskHost: false });
  const meta = parseLinkMeta(redacted);
  const toolLines = sectionLines(redacted, '## Tool calls');
  const adapterLine = toolLines.join('\n').match(/^- \*\*Adapter\*\*:\s*(.+)$/m);
  const indexEntry = findIndexEntry(cwd, filePath);
  const failedOn = indexEntry ? failedOnFromIndex(indexEntry) : false;
  const risk = parseRiskSummaryMarkdown(redacted).maxSeverity ?? 'none';
  const exitCode: 0 | 2 = ok ? 0 : 2;
  const failed = failedOn || status === 'FAILED';
  const signed = signature.present && signature.ok === true;
  const receipt = redactTree({
    id,
    timestamp: meta.timestamp,
    agent: meta.agent,
    adapter: adapterLine?.[1]?.trim() || null,
    risk,
    exitCode,
    failed,
    signed,
    verify: { status, reason: status === 'OK' ? '' : reason },
    policyHits: parsePolicyHits(sectionLines(redacted, '## Policy packs')),
    session: meta.session,
    host: meta.host,
    parent: meta.parent,
    message: headerValue(redacted, 'Message'),
    commands: parseCommands(sectionLines(redacted, '## Commits')),
    files: parseFiles(sectionLines(redacted, '## Files changed')),
    toolCalls: parseToolCalls(toolLines),
    gate: { exitCode, failed, risk, failedOn },
    signature: publicSignature(signature),
    keyless: keylessInfo(filePath),
    attestation: attestationInfo(filePath),
    hashChain: hashChainFor(cwd, reported.sha256),
    sha256: reported.sha256,
  }) as ViewerReceipt;
  const aliases = ref.aliases.filter((alias) => safePublicId(alias));
  return { receipt, aliases };
}

export function buildViewerCatalog(opts: ViewerBuildOptions): ViewerCatalog {
  const store = loadTrustedFingerprints(opts.cwd, { extra: opts.trustedKeys });
  const byId = new Map<string, ViewerReceipt>();
  const receipts: ViewerReceipt[] = [];
  for (const filePath of listReceiptFiles(opts.cwd, opts.receiptsDir)) {
    const built = buildReceipt(opts.cwd, filePath, opts.requireSig === true, store);
    if (!built) continue;
    if (byId.has(built.receipt.id)) continue;
    receipts.push(built.receipt);
    byId.set(built.receipt.id, built.receipt);
    for (const alias of built.aliases) {
      if (!byId.has(alias)) byId.set(alias, built.receipt);
    }
  }
  receipts.sort(byTime);
  const snapshot: ViewerSnapshot = {
    receipts,
    sessions: buildSessions(receipts),
  };
  return { snapshot, byId };
}

export function summarizeReceipt(receipt: ViewerReceipt): ViewerListItem {
  return {
    id: receipt.id,
    timestamp: receipt.timestamp,
    agent: receipt.agent,
    adapter: receipt.adapter,
    risk: receipt.risk,
    exitCode: receipt.exitCode,
    failed: receipt.failed,
    signed: receipt.signed,
    verify: receipt.verify,
    policyHits: receipt.policyHits,
    session: receipt.session,
    host: receipt.host,
    parent: receipt.parent,
    message: receipt.message,
  };
}

export function verifyPayload(receipt: ViewerReceipt): {
  id: string;
  status: 'OK' | 'FAILED';
  ok: boolean;
  reason: string;
  exitCode: 0 | 2;
  sha256: string;
  signature: ViewerSignature;
} {
  return {
    id: receipt.id,
    status: receipt.verify.status,
    ok: receipt.verify.status === 'OK',
    reason: receipt.verify.status === 'OK' ? '' : receipt.verify.reason,
    exitCode: receipt.exitCode,
    sha256: receipt.sha256,
    signature: receipt.signature,
  };
}

function expectedHost(host: string, port: number): string {
  return host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;
}

function forbiddenPath(rawPath: string): boolean {
  if (rawPath.includes('\\') || rawPath.includes('\0') || rawPath.includes('..') || rawPath.includes('//')) {
    return true;
  }
  let decoded: string;
  try {
    decoded = decodeURIComponent(rawPath);
  } catch {
    return true;
  }
  if (decoded.includes('%') || decoded.includes('..') || decoded.includes('\\') || decoded.includes('\0') || decoded.includes('//')) {
    return true;
  }
  return false;
}

function send(
  res: ServerResponse,
  status: number,
  body: string,
  headers: Record<string, string>,
): void {
  const buf = Buffer.from(body, 'utf8');
  res.writeHead(status, {
    ...headers,
    'Content-Length': String(buf.length),
    Connection: 'close',
  });
  res.end(buf);
}

function securityHeaders(csp: string, extra: Record<string, string> = {}): Record<string, string> {
  return {
    'Content-Security-Policy': csp,
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'Cache-Control': 'no-store',
    ...extra,
  };
}

function jsonError(res: ServerResponse, status: number, error: string, extra: Record<string, string> = {}): void {
  send(res, status, `${JSON.stringify({ error })}\n`, securityHeaders(API_CSP, {
    'Content-Type': 'application/json; charset=utf-8',
    ...extra,
  }));
}

export function createViewerServer(catalog: ViewerCatalog, bound: { host: string; port: number }): Server {
  const page = renderViewerPage(null, true);
  const pageCsp = viewerContentSecurityPolicy(true);
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    req.resume();
    const hostHeader = req.headers.host;
    const expected = expectedHost(bound.host, bound.port);
    if (!hostHeader || hostHeader.toLowerCase() !== expected.toLowerCase()) {
      jsonError(res, 403, 'forbidden');
      return;
    }
    if (req.method !== 'GET') {
      jsonError(res, 405, 'method not allowed', { Allow: 'GET' });
      return;
    }
    const rawUrl = req.url || '/';
    const pathOnly = rawUrl.split('?')[0] || '/';
    if (forbiddenPath(pathOnly)) {
      jsonError(res, 403, 'forbidden');
      return;
    }
    let pathname = pathOnly;
    try {
      pathname = decodeURIComponent(pathOnly);
    } catch {
      jsonError(res, 403, 'forbidden');
      return;
    }
    if (pathname === '/' || pathname === '/index.html') {
      send(res, 200, page, securityHeaders(pageCsp, { 'Content-Type': 'text/html; charset=utf-8' }));
      return;
    }
    if (pathname === '/api/receipts') {
      const body = stableJson({ receipts: catalog.snapshot.receipts.map(summarizeReceipt) });
      send(res, 200, body, securityHeaders(API_CSP, { 'Content-Type': 'application/json; charset=utf-8' }));
      return;
    }
    if (pathname === '/api/sessions') {
      send(
        res,
        200,
        stableJson({ sessions: catalog.snapshot.sessions }),
        securityHeaders(API_CSP, { 'Content-Type': 'application/json; charset=utf-8' }),
      );
      return;
    }
    const receiptMatch = pathname.match(/^\/api\/receipts\/([^/]+)$/);
    const verifyMatch = pathname.match(/^\/api\/verify\/([^/]+)$/);
    const id = receiptMatch?.[1] ?? verifyMatch?.[1];
    if (receiptMatch || verifyMatch) {
      if (!id || !safePublicId(id)) {
        jsonError(res, 403, 'forbidden');
        return;
      }
      const receipt = catalog.byId.get(id);
      if (!receipt) {
        jsonError(res, 404, 'not found');
        return;
      }
      const body = receiptMatch ? stableJson({ receipt }) : stableJson(verifyPayload(receipt));
      send(res, 200, body, securityHeaders(API_CSP, { 'Content-Type': 'application/json; charset=utf-8' }));
      return;
    }
    jsonError(res, 404, 'not found');
  });
}
