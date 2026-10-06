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
// Windows keeps the mouse cursor on whole physical pixels, so every screenX and screenY a real mouse produces, times
// the display scale, is a whole number: 326 of 326 moves in Edge and Chrome, at 100%, 125% and 150% scaling and at page
// zooms from 90% to 200%. Page zoom is part of devicePixelRatio but not of screenX, so the scale is devicePixelRatio
// itself or a Windows scale that a Chrome zoom level turns into it. Scripted moves land between pixels unless the
// script works out the grid: 40 of 40 and 80 of 123 moves off it. The zoom levels tried are limited by the window:
// the page (innerHeight, zoomed) fits inside the window (outerHeight), under at most 300px of toolbars.
export const GRID_MIN_MOVES = 10;
export const GRID_MIN_SHARE = 0.8;
const WINDOWS_SCALES = [1, 1.25, 1.5, 1.75, 2, 2.25, 2.5, 3, 3.5, 4, 4.5, 5];
const CHROME_ZOOMS = [0.25, 1 / 3, 0.5, 2 / 3, 0.75, 0.8, 0.9, 1, 1.1, 1.25, 1.5, 1.75, 2, 2.5, 3, 4, 5];
export function pixelGridShare(points, dpr, [outer, inner] = []) {
  const sized = Number.isFinite(outer) && Number.isFinite(inner) && inner > 0;
  const zooms = sized ? CHROME_ZOOMS.filter(zoom => zoom >= (outer - 300) / inner && zoom <= outer / inner * 1.02) : CHROME_ZOOMS;
  const scales = [dpr, ...WINDOWS_SCALES.filter(scale => zooms.some(zoom => Math.abs(scale * zoom - dpr) < 0.005 * dpr))];
  const whole = v => Math.abs(v - Math.round(v)) < 0.02;
  return Math.max(...scales.map(scale => points.filter(([x, y]) => whole(x * scale) && whole(y * scale)).length / points.length));
}

// A key held down repeats after at most a second on Windows (its longest delay setting), so a held Space or Enter
// sends repeated keydowns before the hold completes. A script that presses once and waits sends one.
export const KEY_REPEAT_HOLD_MS = 1200;

// A DevTools client that intercepts requests holds each one until it answers, cache hits included. patchright does this
// on every page, as do Playwright and Puppeteer scripts that route requests. The check page fetches one cached byte 8
// times in a row from the page and from a shared worker, which such a client does not reach, and reports the fastest of
// 6 rounds for each. A person's Edge and Chrome: page 1.0 to 1.25 times the worker, also under load and with an
// extension watching every request (it sees both), and up to 1.5 with DevTools open. patchright: 2.6 to 3.4 times, 0.65
// ms or more per fetch. Measured on Windows only.
export const INTERCEPTION_RATIO = 2;
export const INTERCEPTION_MIN_MS = 0.3;

// Firefox on Windows stamps a mouse move with the time of the Windows message it came from, which counts in system
// clock ticks of 15.6 ms, so the time from that stamp to the page's handler wanders over most of a tick: the middle half
// of a person's moves spread over 9 to 10 ms, and any 16 moves in a row over 5 ms or more (Firefox 157, slow and fast
// moves; 4 or 5 ms over a whole sample from a tool that moves the cursor right on each tick). Moves that Playwright's
// Firefox makes through Juggler, the protocol Camoufox uses too, carry the time they were made: 0 to 2 ms, the middle
// half within 1 ms, headed or headless, paused or not. Judged only with a clock of 1 ms or finer (resistFingerprinting
// coarsens it, and also claims Windows on every system), and only on Windows: elsewhere real moves carry exact times.
export const EVENT_TIME_MIN_MOVES = 16;
export const EVENT_TIME_MAX_SPREAD_MS = 2;
export function lagSpread(lags) {
  const sorted = [...lags].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length * 3 / 4)] - sorted[Math.floor(sorted.length / 4)];
}

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
  // [screenX, screenY] of the last 64 mouse moves, devicePixelRatio and [outerHeight, innerHeight], from the probe.
  const points = (Array.isArray(value.points) ? value.points.slice(-64) : []).filter(point => Array.isArray(point) && point.length === 2 && point.every(Number.isFinite));
  const dpr = Number.isFinite(value.dpr) && value.dpr >= 0.25 && value.dpr <= 25 ? value.dpr : null;
  const heights = Array.isArray(value.heights) && value.heights.length === 2 && value.heights.every(Number.isFinite) ? value.heights : [];
  const grid = dpr && points.length >= GRID_MIN_MOVES ? pixelGridShare(points, dpr, heights) : null;
  if (grid !== null && chromium && pointer === 'mouse' && windowsDesktop(userAgent) && grid < GRID_MIN_SHARE) found.push('off_grid_pointer');
  // Touch input on a Windows PC that reports no multi-touch screen, or on a Mac (Macs have no touchscreen): what the
  // DevTools protocol's touch emulation produces. Windows touchscreens report 5 or more touch points.
  const touchPoints = Number.isSafeInteger(value.env?.touch) ? value.env.touch : null;
  if (pointer === 'touch' && touchPoints !== null && ((windowsDesktop(userAgent) && touchPoints < 2) || (/Macintosh/.test(userAgent) && touchPoints === 0))) found.push('emulated_touch');
  // [page ms, shared worker ms, fetches each], the fastest round of cached fetches from each side.
  const fetches = Array.isArray(value.fetches) && value.fetches.length === 3 && value.fetches.every(n => Number.isFinite(n) && n >= 0)
    && Number.isSafeInteger(value.fetches[2]) && value.fetches[2] >= 4 && value.fetches[1] > 0 ? value.fetches : null;
  const held = fetches ? fetches[0] / fetches[1] : null;
  if (held !== null && chromium && windowsDesktop(userAgent) && held >= INTERCEPTION_RATIO && (fetches[0] - fetches[1]) / fetches[2] >= INTERCEPTION_MIN_MS) found.push('request_interception');
  // How long each of the last 64 mouse moves took from its time stamp to the page's handler, and the clock's step.
  const lags = (Array.isArray(value.lags) ? value.lags.slice(-64) : []).filter(lag => Number.isFinite(lag) && lag > -1 && lag < 60000);
  const clock = Number.isFinite(value.clock) ? value.clock : null;
  const gecko = value.engine === 'gecko' || (/Firefox\//.test(userAgent) && value.engine !== 'chromium');
  const spread = gecko && clock !== null && clock > 0 && clock <= 1.5 && lags.length >= EVENT_TIME_MIN_MOVES ? lagSpread(lags) : null;
  if (spread !== null && pointer === 'mouse' && windowsDesktop(userAgent) && spread <= EVENT_TIME_MAX_SPREAD_MS) found.push('synthetic_event_time');
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
      ...(input && pointer === 'mouse' ? [`predicted:${input[1]}/${input[0]}`] : []), ...(grid !== null && pointer === 'mouse' ? [`grid:${grid.toFixed(2)}`] : []), ...(pointer === 'keyboard' ? [`repeats:${repeats}`] : []),
      ...(devtools === null ? [] : [`devtools:${devtools.toFixed(2)}`]), ...(worker === null ? [] : [`worker:${worker.toFixed(2)}`]), ...(held === null ? [] : [`fetches:${held.toFixed(2)}`]),
      ...(spread !== null && pointer === 'mouse' ? [`lag-spread:${+spread.toFixed(1)}/${lags.length}`] : [])],
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
