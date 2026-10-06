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

// Playwright, Puppeteer and most AI-agent browsers drive Chromium over the DevTools protocol, which makes V8 serialise
// everything the page logs. The check page times logging four Errors against logging four numbers (median of 7 rounds):
// 1.2 to 1.6 in a person's Edge, even under load, and 4.4 or more with a DevTools client attached (field-measured, see
// the threat model). An open DevTools window counts too. Firefox and Safari log differently and are not judged.
export const DEVTOOLS_RATIO = 3;
// Logging Errors never costs less than logging numbers. Far below 1 means console.debug was replaced to hide the client.
export const CONSOLE_TAMPERED_RATIO = 0.5;
const chromiumUA = userAgent => /Chrome\//.test(userAgent) && !/Firefox|CriOS|EdgiOS|FxiOS/.test(userAgent);

// Desktop Firefox keeps the check page in its back/forward cache when the page steps to the gate's hop page and back.
// Camoufox and Playwright's Firefox switch that cache off, so they load the page again (the gateway refuses that reload).
// Judged by the engine the page found, so a Firefox build claiming to be Chrome still has to make the trip. Firefox on
// Android is not measured and does not make it.
export function backForwardRequired(report, userAgent = '') {
  const engine = report?.engine;
  const gecko = engine === 'gecko' || (/Firefox\//.test(userAgent) && !/FxiOS/.test(userAgent) && engine !== 'chromium');
  const handheld = /Android/.test(userAgent) && Number(report?.env?.touch) > 0;
  return gecko && !handheld;
}

// Chromium predicts where a moving pointer goes next (PointerEvent.getPredictedEvents) once moves arrive every few
// milliseconds, as they do from a mouse or touchpad: 27 to 111 of every person's moves on Windows carried predictions,
// all but the first few after the hand starts. patchright driving installed Edge, moving like a hand but with a round
// trip and a pause per step, got none in 83 moves, and 5 of 47 with a real mouse also crossing its window. A script that
// sends its moves faster gets predictions too, so this catches unhurried scripts, not every script (see the threat
// model). Measured on Windows only.
export const PREDICTED_MIN_MOVES = 10;
export const PREDICTED_MIN_SHARE = 0.2;
const windowsDesktop = userAgent => /Windows NT/.test(userAgent) && !/Mobile|Android/.test(userAgent);
// A key held down repeats after at most a second on Windows (its longest delay setting), so a held Space or Enter
// sends repeated keydowns before the hold completes. A script that presses once and waits sends one.
export const KEY_REPEAT_HOLD_MS = 1200;

// What the human-check page reports. Every field is client-controlled, so missing or malformed values count against it.
// `returned` says whether this check's page came back from the hop page without loading again (null: not judged).
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
  if (value.automationGlobals === true) found.push('automation_globals');
  // Desktop Chrome always has a window frame and its built-in PDF viewer plugins; headless Chrome has neither.
  const frameless = frame?.[0] === 0 && frame?.[1] === 0 && plugins === 0 && /Chrome\//.test(userAgent) && !/Mobile/.test(userAgent);
  if (declaredUA.test(userAgent) || /HeadlessChrome/i.test(brands) || frameless) found.push('headless');
  if (pointer === 'mouse' && syntheticPath(path)) found.push('synthetic_pointer');
  if (returned === false && backForwardRequired(value, userAgent)) found.push('no_back_forward_cache');
  const devtools = Number.isFinite(value.devtools) ? Math.max(0, Math.min(value.devtools, 1000)) : null;
  // By user agent or by the engine the page found, so Chromium claiming to be Firefox is still timed.
  const chromium = chromiumUA(userAgent) || value.engine === 'chromium';
  if (devtools !== null && chromium && devtools >= DEVTOOLS_RATIO) found.push('devtools_protocol');
  // The same timing from a worker, which page-level console hooks do not reach. Where the page measured, a missing or
  // unreadable worker report means something stood in the way.
  const worker = value.worker && Number.isFinite(value.worker.devtools) ? Math.max(0, Math.min(value.worker.devtools, 1000)) : null;
  if (worker !== null && chromium && worker >= DEVTOOLS_RATIO && !found.includes('devtools_protocol')) found.push('devtools_protocol');
  if ((chromium && devtools !== null && devtools < CONSOLE_TAMPERED_RATIO) || (chromium && worker !== null && worker < CONSOLE_TAMPERED_RATIO)
    || (chromium && devtools !== null && 'worker' in value && worker === null) || value.hooked === true
    || (chromium && (value.touched === false || (value.worker && value.worker.touched === false)))) found.push('console_tampered');
  // [moves, moves with predictions], counted by the probe for the mouse.
  const input = Array.isArray(value.input) && value.input.length === 2 && value.input.every(n => Number.isSafeInteger(n) && n >= 0) ? value.input : null;
  if (input && chromium && pointer === 'mouse' && windowsDesktop(userAgent) && input[0] >= PREDICTED_MIN_MOVES && input[1] < input[0] * PREDICTED_MIN_SHARE) found.push('no_predicted_input');
  // Touch input on a Windows PC that reports no multi-touch screen, or on a Mac (Macs have no touchscreen): what the
  // DevTools protocol's touch emulation produces. Windows touchscreens report 5 or more touch points.
  const touchPoints = Number.isSafeInteger(value.env?.touch) ? value.env.touch : null;
  if (pointer === 'touch' && touchPoints !== null && ((windowsDesktop(userAgent) && touchPoints < 2) || (/Macintosh/.test(userAgent) && touchPoints === 0))) found.push('emulated_touch');
  const repeats = Number.isSafeInteger(value.repeats) && value.repeats >= 0 ? value.repeats : 0;
  const unrepeated = pointer === 'keyboard' && windowsDesktop(userAgent) && holdMs >= KEY_REPEAT_HOLD_MS && repeats === 0;
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
    // A key held on Windows that never repeated. People with key repeat switched off land here too, so this fails the
    // check (the page suggests the pointer) rather than calling the browser automated.
    unrepeated,
    notes: [...found, ...(unrepeated ? ['no_key_repeat'] : []), `pointer:${pointer}`, `moves:${path.length ? path.length + 1 : 0}`,
      ...(input && pointer === 'mouse' ? [`predicted:${input[1]}/${input[0]}`] : []), ...(pointer === 'keyboard' ? [`repeats:${repeats}`] : []),
      ...(devtools === null ? [] : [`devtools:${devtools.toFixed(2)}`]), ...(worker === null ? [] : [`worker:${worker.toFixed(2)}`])],
  };
}

// Chrome, Edge, Brave and Opera name themselves in their brand list. Playwright's and Puppeteer's bundled browsers
// say only "Chromium" plus a placeholder ("Not_A Brand"). A few rebuilt browsers do too, so this asks, it does not block.
const PLACEHOLDER_BRAND = /^Not.?A.?Brand$/i;
export function unbrandedChromium(brands) {
  const names = brands.filter(Boolean);
  return names.length > 0 && names.every(name => name === 'Chromium' || PLACEHOLDER_BRAND.test(name));
}
const headerBrands = value => [...String(value ?? '').matchAll(/"([^"]*)"\s*;\s*v=/g)].map(match => match[1]);

// Requests that no current browser would send. Modern Chrome and Firefox always send Fetch Metadata, Chromium also
// sends client hints in secure contexts, and every browser sends a language with page loads. Scripts usually skip them.
export function headerAnomaly(headers, { document = false, secureContext = true } = {}) {
  const ua = headers['user-agent'] ?? '';
  if (!/^Mozilla\/5\.0 \(/.test(ua)) return 'not_a_browser';
  const chrome = /(?:Chrome|Chromium)\/(\d+)/.exec(ua), firefox = /Firefox\/(\d+)/.exec(ua);
  if (((chrome && +chrome[1] >= 90) || (firefox && +firefox[1] >= 90)) && !headers['sec-fetch-mode']) return 'missing_fetch_metadata';
  // Android in-app browsers (WebView) and Chrome on iOS do not send client hints.
  if (secureContext && chrome && +chrome[1] >= 90 && !/; wv\)|CriOS|Firefox/.test(ua) && !headers['sec-ch-ua']) return 'missing_client_hints';
  // Desktop only: Android and Linux builds of Chromium are common among people.
  if (headers['sec-ch-ua'] && /Windows NT|Macintosh/.test(ua) && unbrandedChromium(headerBrands(headers['sec-ch-ua']))) return 'unbranded_chromium';
  // Node's fetch fills in `*`, which no browser sends.
  if (document && (headers['accept-language'] ?? '*').trim() === '*') return 'missing_language';
  return null;
}
