import { automationSignals } from './automation.mjs';

// The basic detection rules: what this repository ships. They catch automation that declares itself and agents that
// press without moving, nothing subtler. A rules pack (see rules.mjs) replaces all of this with its own exports.

// The measuring script each check sends, scrambled per check by scramble.mjs. `worker` is an optional second script the
// page can start as a Web Worker (served at /_gate/human/probe-worker.js); the basic one needs none.
export const probe = { page: new URL('../web/probe.template.js', import.meta.url), worker: null };
// Extra files served under /_gate/, by path: { file, type, cache? }. A pack can bring its own.
export const assets = {};

// What the human-check page reports. Every field is client-controlled, so missing or malformed values count against it.
// `returned` is the result of the check page's hop (null: none); the basic rules do not use it.
export function humanReport(report, userAgent = '', { returned = null } = {}) {
  const value = report && typeof report === 'object' && !Array.isArray(report) ? report : {};
  const holdMs = Number.isFinite(value.holdMs) ? Math.max(0, Math.min(value.holdMs, 600000)) : 0;
  const pointer = ['mouse', 'touch', 'pen', 'keyboard'].includes(value.pointer) ? value.pointer : 'unknown';
  const path = (Array.isArray(value.path) ? value.path.slice(-64) : [])
    .filter(step => Array.isArray(step) && step.length === 3 && step.every(Number.isFinite));
  const frame = Array.isArray(value.frame) && value.frame.length === 2 && value.frame.every(Number.isFinite) ? value.frame : null;
  const plugins = Number.isSafeInteger(value.plugins) ? value.plugins : null;
  const brands = typeof value.brands === 'string' ? value.brands.slice(0, 300) : '';
  const found = [];
  if (value.webdriver === true) found.push('webdriver');
  // Desktop Chrome always has a window frame and its built-in PDF viewer plugins; headless Chrome has neither.
  const frameless = frame?.[0] === 0 && frame?.[1] === 0 && plugins === 0 && /Chrome\//.test(userAgent) && !/Mobile/.test(userAgent);
  if (automationSignals(userAgent).length || /HeadlessChrome/i.test(brands) || frameless) found.push('headless');
  return {
    automated: found.length > 0,
    trusted: value.trusted === true,
    holdMs,
    // A mouse that reaches the button without moving at all: how agent click tools press. Touch and keys never hover.
    jumped: pointer === 'mouse' && path.length < 2,
    // Part of the rules interface. Not judged here.
    unrepeated: false,
    notes: [...found, `pointer:${pointer}`, `moves:${path.length ? path.length + 1 : 0}`],
  };
}

// Requests no current browser would send: a user agent that is not a browser's, or a modern Chrome or Firefox without
// Fetch Metadata. Used in `suspicious` mode to decide who gets the check.
export function headerAnomaly(headers) {
  const ua = headers['user-agent'] ?? '';
  if (!/^Mozilla\/5\.0 \(/.test(ua)) return 'not_a_browser';
  const chrome = /(?:Chrome|Chromium)\/(\d+)/.exec(ua), firefox = /Firefox\/(\d+)/.exec(ua);
  if (((chrome && +chrome[1] >= 90) || (firefox && +firefox[1] >= 90)) && !headers['sec-fetch-mode']) return 'missing_fetch_metadata';
  return null;
}

// Server traits add up to a score: SANDBOX_BLOCK_SCORE or more is refused, SANDBOX_STRICT_SCORE or more gets a pass that
// lasts an hour (SANDBOX_CHECK=enforce). The basic rules score only a datacenter address, which VPNs share with servers.
export const SANDBOX_BLOCK_SCORE = 4;
export const SANDBOX_STRICT_SCORE = 2;
export function sandboxReport(env, userAgent = '', { datacenter = false } = {}) {
  const found = datacenter ? ['datacenter'] : [];
  const score = datacenter ? 2 : 0;
  return { score, found, notes: [...found, `sandbox:${score}`] };
}
