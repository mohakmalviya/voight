// These are declarations, not proof of humanity. Clients can suppress both signals.
const declaredUA = /(?:^|[\s;(])(?:HeadlessChrome|Playwright|Puppeteer|Selenium)(?:[\/\s;)]|$)/i;

export function automationSignals(userAgent, webdriver = null) {
  const signals = [];
  if (declaredUA.test(userAgent)) signals.push('declared_user_agent');
  if (webdriver === true) signals.push('webdriver');
  return signals;
}

export function reportedWebdriver(body) {
  const report = body?.clientSignals;
  return report && !Array.isArray(report) && typeof report.webdriver === 'boolean' ? report.webdriver : null;
}

export function automationDecision(mode, userAgent, webdriver, requireReport = true) {
  if (mode !== 'enforce') return null;
  if (automationSignals(userAgent, webdriver).length) return 'automation_declared';
  if (requireReport && webdriver === null) return 'automation_report_required';
  return null;
}

// Scripted pointers (Playwright, Puppeteer and friends) glide in identical steps. A hand never repeats
// the same multi-pixel step over and over; tiny 1px creeps are ignored so slow, careful people are not flagged.
// Counting the most common step, rather than consecutive repeats, survives real mouse events mixed into the path.
export function syntheticPath(path) {
  const counts = new Map();
  let steps = 0;
  for (const [dx, dy] of path) {
    if (Math.hypot(dx, dy) < 2) continue;
    const key = `${dx.toFixed(2)},${dy.toFixed(2)}`;
    counts.set(key, (counts.get(key) ?? 0) + 1); steps++;
  }
  const top = Math.max(0, ...counts.values());
  return top >= 10 && top / steps >= 0.5;
}

// What the human-check page reports. Every field is client-controlled, so missing or malformed values count against it.
export function humanReport(report, userAgent = '') {
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
  if (value.automationGlobals === true) found.push('automation_globals');
  // Desktop Chrome always has a window frame and its built-in PDF viewer plugins; headless Chrome has neither.
  const frameless = frame?.[0] === 0 && frame?.[1] === 0 && plugins === 0 && /Chrome\//.test(userAgent) && !/Mobile/.test(userAgent);
  if (declaredUA.test(userAgent) || /HeadlessChrome/i.test(brands) || frameless) found.push('headless');
  if (pointer === 'mouse' && syntheticPath(path)) found.push('synthetic_pointer');
  const gap = value.pressGap, final = path.at(-1);
  return {
    automated: found.length > 0,
    trusted: value.trusted === true,
    holdMs,
    // A mouse that reaches the button without moving, arrives in one long leap, or presses away from where it
    // last moved has teleported: that is how agent click tools behave. People slow down before pressing.
    // Touch and keys never hover.
    jumped: pointer === 'mouse' && (path.length < 2 || Math.hypot(final[0], final[1]) > 80
      || !(Number.isFinite(gap) && gap >= 0 && gap <= 3)),
    notes: [...found, `pointer:${pointer}`, `moves:${path.length ? path.length + 1 : 0}`],
  };
}

// Requests that no current browser would send. Modern Chrome and Firefox always send Fetch Metadata, Chromium also
// sends client hints in secure contexts, and every browser sends a language with page loads. Scripts usually skip them.
export function headerAnomaly(headers, { document = false, secureContext = true } = {}) {
  const ua = headers['user-agent'] ?? '';
  if (!/^Mozilla\/5\.0 \(/.test(ua)) return 'not_a_browser';
  const chrome = /(?:Chrome|Chromium)\/(\d+)/.exec(ua), firefox = /Firefox\/(\d+)/.exec(ua);
  if (((chrome && +chrome[1] >= 90) || (firefox && +firefox[1] >= 90)) && !headers['sec-fetch-mode']) return 'missing_fetch_metadata';
  // Android in-app browsers (WebView) and Chrome on iOS do not send client hints.
  if (secureContext && chrome && +chrome[1] >= 90 && !/; wv\)|CriOS|Firefox/.test(ua) && !headers['sec-ch-ua']) return 'missing_client_hints';
  // Node's fetch fills in `*`, which no browser sends.
  if (document && (headers['accept-language'] ?? '*').trim() === '*') return 'missing_language';
  return null;
}
