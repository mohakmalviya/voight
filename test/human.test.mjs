import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { createFixture } from './fixture.mjs';
import { leadingZeroBits } from '../src/gateway.mjs';
import { humanReport, headerAnomaly, unbrandedChromium, backForwardRequired } from '../src/automation.mjs';
import { declaredAIAgent } from '../src/agents.mjs';
import { Store } from '../src/store.mjs';
import { cloudRanges, sandboxReport } from '../src/sandbox.mjs';
import { scrambledProbe, sealReport, openReport } from '../src/scramble.mjs';

const ASSETS = { '/_gate/index.html': { body: '<h1>Admission required</h1>', type: 'text/html' } };
// A hand slowing down onto the button: uneven steps, roughly one per frame.
const HAND = [[18.4, 6.1, 16], [15.2, 5.5, 17], [12.9, 3.8, 16], [9.1, 3.3, 17], [6.6, 1.2, 16], [3.9, 1.7, 17], [2.1, 0.4, 16], [0.8, 0.3, 17]];
const HUMAN = { webdriver: false, automationGlobals: false, trusted: true, holdMs: 1600, pointer: 'mouse', path: HAND, pressGap: 0, frame: [16, 88], plugins: 5, brands: 'Chromium|Google Chrome' };
// What Playwright's mouse.move(x, y, { steps }) produces.
const SCRIPTED = Array.from({ length: 24 }, () => [14.4, 7.6, 17]);
// The same script while the real mouse also moves over its window: stray operating-system events mixed in.
const NOISY = SCRIPTED.flatMap((step, i) => i % 3 ? [step] : [step, [-220 + i, 140 - i, 3], [218 - i, -137 + i, 14]]);
// Google's documented pattern: crawl-66-249-66-1.googlebot.com resolves back to 66.249.66.1.
const resolver = {
  async reverse(ip) {
    const names = { '66.249.66.1': ['crawl-66-249-66-1.googlebot.com'], '203.0.113.66': ['crawl.googlebot.com.evil.example'], '198.51.100.7': ['fake.googlebot.com'] };
    if (!names[ip]) throw Object.assign(new Error('not found'), { code: 'ENOTFOUND' });
    return names[ip];
  },
  async lookup(name) {
    return { 'crawl-66-249-66-1.googlebot.com': [{ address: '66.249.66.1', family: 4 }], 'fake.googlebot.com': [{ address: '192.0.2.200', family: 4 }] }[name] ?? [];
  },
};

async function fixture(t, overrides = {}, env = {}) {
  const f = await createFixture({ challengeDifficulty: 4, resolver, ...overrides }, undefined, ASSETS, { MODE: 'public', TRUSTED_PROXIES: '127.0.0.1', HUMAN_CHECK: 'always', ...env });
  t.after(f.close); return f;
}
const visitor = (ip = '203.0.113.10', extra = {}) => ({ 'x-forwarded-for': ip, ...extra });
const page = { accept: 'text/html' };
function solve(challenge, difficulty) {
  for (let nonce = 0; ; nonce++) {
    if (leadingZeroBits(createHash('sha256').update(`${challenge}:${nonce}`).digest()) >= difficulty) return String(nonce);
  }
}
// Runs the check the way the page does: ask, hold for a moment, then send the report sealed with this check's key.
const probeKey = (f, cookie) => f.store.peekChallenge(cookie.split('=')[1]).probe.key;
async function check(f, { signals = {}, wait = 1600, headers = visitor(), verifyHeaders = headers, nonce, report, hop } = {}) {
  const issued = await f.post('/_gate/human/options', hop ? { hop } : {}, null, headers);
  assert.equal(issued.status, 200);
  const { challenge, difficulty, holdMs } = await issued.json();
  assert.equal(holdMs, 1500);
  f.advance(wait);
  const cookie = f.cookieOf(issued);
  return f.post('/_gate/human/verify', { nonce: nonce ?? solve(challenge, difficulty), report: report ?? sealReport({ ...HUMAN, ...signals }, probeKey(f, cookie)) }, cookie, verifyHeaders);
}
async function get(f, path, headers) {
  const response = await f.request(path, { headers });
  return { status: response.status, text: await response.text() };
}
const errorOf = async response => (await response.json()).error;

test('a new visitor gets the human check, and nothing reaches the site before it passes', async t => {
  const f = await fixture(t);
  const html = await get(f, '/article', visitor('203.0.113.10', page));
  assert.equal(html.status, 403);
  assert.match(html.text, /Confirm you are human[\s\S]*\/_gate\/human\.js/);
  assert.match(html.text, /for up to 6 hours on this browser/);
  const api = await f.request('/data.json', { headers: visitor() });
  assert.equal(api.status, 403); assert.equal(await errorOf(api), 'human_check_required');
  assert.equal((await get(f, '/robots.txt', visitor())).status, 200); // Crawlers can always read the rules.
  assert.equal(f.hits(), 1);
});

test('holding the button with a real gesture earns a six-hour pass bound to this browser', async t => {
  const f = await fixture(t);
  const passed = await check(f);
  assert.equal(passed.status, 200, await passed.clone().text());
  assert.match(passed.headers.get('set-cookie'), /^hg_human=[\w-]{43}; Path=\/; HttpOnly; SameSite=Lax; Max-Age=21600/);
  const cookie = f.cookieOf(passed);
  assert.equal((await get(f, '/article', visitor('203.0.113.10', { ...page, cookie }))).text, 'PRIVATE_ORIGIN_CONTENT');
  // A new network address (mobile carriers rotate them) keeps the pass; another client copying the cookie does not.
  assert.equal((await get(f, '/next', visitor('198.51.100.20', { cookie }))).status, 200);
  assert.equal((await get(f, '/next', visitor('203.0.113.10', { cookie, 'user-agent': 'scraper/1.0' }))).status, 403);
  const issued = f.audit.find(event => event.reason === 'human_pass_issued');
  assert.deepEqual(issued.automationSignals, ['pointer:mouse', 'moves:9', 'sandbox:0']);
  f.advance(21601 * 1000);
  assert.equal((await get(f, '/later', visitor('203.0.113.10', { cookie }))).status, 403); // Passes expire.
});

test('automation is caught even when it performs the hold, and a claimed hold must really take time', async t => {
  const f = await fixture(t);
  const cases = [
    [{ signals: { webdriver: true } }, 403, 'automation_detected'],
    [{ signals: { brands: 'HeadlessChrome|Chromium' } }, 403, 'automation_detected'],
    [{ signals: { frame: [0, 0], plugins: 0 }, headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0) Chrome/141.0 Safari/537.36' } }, 403, 'automation_detected'],
    [{ signals: { path: SCRIPTED } }, 403, 'automation_detected'],
    [{ signals: { path: SCRIPTED.slice(0, 9).concat(HAND).concat(NOISY) } }, 403, 'automation_detected'],
    [{ signals: { path: [[300, 120, 1]] } }, 403, 'human_check_failed'], // Jumped onto the button, like agent click tools.
    [{ signals: { pressGap: 260 } }, 403, 'human_check_failed'], // Moved somewhere, then pressed elsewhere: a teleport.
    [{ signals: { path: HAND.concat([[191.2, -8.4, 83]]) } }, 403, 'human_check_failed'], // Real mouse noise, then one leap onto the button.
    [{ signals: { pressGap: undefined } }, 403, 'human_check_failed'],
    [{ signals: { automationGlobals: true } }, 403, 'automation_detected'],
    // Playwright, Puppeteer or an agent attached to the browser over the DevTools protocol.
    [{ signals: { devtools: 4.47 }, headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0) Chrome/141.0 Safari/537.36' } }, 403, 'automation_detected'],
    [{ signals: { trusted: false } }, 403, 'human_check_failed'],
    [{ signals: { holdMs: 300 } }, 403, 'human_check_failed'],
    [{ wait: 200 }, 403, 'human_check_failed'], // The page claims a hold the server never saw.
    [{ nonce: 'x' }, 403, 'invalid_solution'],
    [{ verifyHeaders: visitor('203.0.113.10', { 'user-agent': 'other-client' }) }, 403, 'invalid_challenge'],
  ];
  for (const [index, [options, status, reason]] of cases.entries()) {
    const headers = visitor(`203.0.113.${100 + index}`, options.headers);
    const response = await check(f, { headers, ...options, verifyHeaders: options.verifyHeaders && { ...options.verifyHeaders, 'x-forwarded-for': headers['x-forwarded-for'] } });
    assert.equal(response.status, status, reason); assert.equal(await errorOf(response), reason);
  }
  const report = humanReport({ webdriver: 'yes', holdMs: 'long', path: [[1, 'x', 2], 'junk'], pointer: '<script>', frame: 'none' });
  assert.deepEqual(report, { automated: false, trusted: false, holdMs: 0, jumped: false, unrepeated: false, notes: ['pointer:unknown', 'moves:0'] });
  // Touch and keyboard users never hover, and a frameless phone browser is not headless.
  assert.equal(humanReport({ ...HUMAN, pointer: 'touch', path: [] }).jumped, false);
  assert.equal(humanReport({ ...HUMAN, frame: [0, 0], plugins: 0 }, 'Mozilla/5.0 (Linux; Android 15) Chrome/141.0 Mobile Safari/537.36').automated, false);
  // The DevTools timing: a person's Edge measured up to 1.6, an attached client 4.4 or more. Other engines are not judged.
  const chrome = 'Mozilla/5.0 (Windows NT 10.0) Chrome/141.0 Safari/537.36';
  assert.deepEqual(humanReport({ ...HUMAN, devtools: 4.47 }, chrome).notes, ['devtools_protocol', 'pointer:mouse', 'moves:9', 'devtools:4.47']);
  assert.equal(humanReport({ ...HUMAN, devtools: 1.57 }, chrome).automated, false);
  assert.equal(humanReport({ ...HUMAN, devtools: 2.99 }, chrome).automated, false);
  // An attacker who replaces console.debug to hide the client makes both timings vanish.
  assert.deepEqual(humanReport({ ...HUMAN, devtools: 0 }, chrome).notes.slice(0, 1), ['console_tampered']);
  assert.equal(humanReport({ ...HUMAN, devtools: 0.75 }, chrome).automated, false);
  assert.equal(humanReport({ ...HUMAN, devtools: 3 }, 'Mozilla/5.0 (Windows NT 10.0; rv:143.0) Gecko/20100101 Firefox/143.0').automated, false);
  assert.equal(humanReport({ ...HUMAN, devtools: 3 }, 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) CriOS/141.0 Mobile/15E148 Safari/604.1').automated, false);
  for (const devtools of [null, '9', Infinity, NaN]) assert.equal(humanReport({ ...HUMAN, devtools }, chrome).automated, false);
  assert.equal(humanReport({ ...HUMAN, devtools: -5 }, chrome).automated, true); // Impossible from the real page.
  assert.deepEqual(humanReport({ ...HUMAN, devtools: 1.04, worker: { devtools: 5.07 } }, chrome).notes, ['devtools_protocol', 'pointer:mouse', 'moves:9', 'devtools:1.04', 'worker:5.07']);
  assert.equal(humanReport({ ...HUMAN, devtools: 1.3, worker: { devtools: 1.6 } }, chrome).automated, false);
  assert.equal(humanReport({ ...HUMAN, devtools: 1.3, worker: false }, chrome).automated, true);
  // A logged Error that nobody read: the console call never reached the browser.
  assert.equal(humanReport({ ...HUMAN, devtools: 1.3, touched: true, worker: { devtools: 1.2, touched: true } }, chrome).automated, false);
  assert.deepEqual(humanReport({ ...HUMAN, devtools: 1.0, touched: false, worker: { devtools: 1.2, touched: true } }, chrome).notes.slice(0, 1), ['console_tampered']);
  assert.deepEqual(humanReport({ ...HUMAN, devtools: 1.0, touched: true, worker: { devtools: 1.0, touched: false } }, chrome).notes.slice(0, 1), ['console_tampered']);
  assert.equal(humanReport({ ...HUMAN, touched: false }, 'Mozilla/5.0 (Windows NT 10.0; rv:143.0) Gecko/20100101 Firefox/143.0').automated, false);
  assert.equal(humanReport({ ...HUMAN, devtools: null, worker: null }, chrome).automated, false); // Neither measured (no userAgentData).
  // A slow, careful hand creeping one pixel at a time is not mistaken for a script.
  assert.equal(humanReport({ ...HUMAN, path: Array.from({ length: 30 }, () => [1, 0, 17]) }).automated, false);
  assert.deepEqual((await f.post('/_gate/human/verify', { signals: HUMAN }, null, visitor())).status, 403); // No issued check.
});

test('scripted input on Windows is caught: unpredicted moves, emulated touch and a key that never repeats', async t => {
  const edge = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0';
  const firefox = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0';
  const mac = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
  // Measured: a person's mouse 27/32, 45/52 and 111/121 moves with predictions; patchright 0/40, 0/43, and 5/47 with a
  // real mouse also crossing its window.
  for (const input of [[32, 27], [52, 45], [121, 111], [12, 3], [9, 0]]) assert.equal(humanReport({ ...HUMAN, input }, edge).automated, false, String(input));
  assert.deepEqual(humanReport({ ...HUMAN, input: [40, 0] }, edge).notes, ['no_predicted_input', 'pointer:mouse', 'moves:9', 'predicted:0/40']);
  assert.equal(humanReport({ ...HUMAN, input: [47, 5] }, edge).automated, true);
  // Not judged where it was not measured: other engines and other systems.
  for (const ua of [firefox, mac, 'Mozilla/5.0 (X11; Linux x86_64) Chrome/141.0 Safari/537.36']) assert.equal(humanReport({ ...HUMAN, input: [40, 0] }, ua).automated, false, ua);
  for (const input of [[40], [40, -1], [40, 0.5], '40,0', null]) assert.equal(humanReport({ ...HUMAN, input }, edge).automated, false);
  // Screen positions: a real mouse stays on whole physical pixels at any page zoom; scripted moves fall between them.
  const real = (dpr, scale = dpr, n = 20) => ({ dpr, heights: [797, Math.round(706 * scale / dpr)], points: Array.from({ length: n }, (_, i) => [(300 + i * 3) / scale, (400 + (i % 3)) / scale]) });
  for (const [dpr, scale] of [[1.25], [1], [1.5], [1.5625, 1.25], [1.125, 1.25], [1.375, 1.25], [2.5, 1.25], [1.1]]) {
    assert.equal(humanReport({ ...HUMAN, ...real(dpr, scale) }, edge).automated, false, `${dpr} ${scale}`);
  }
  assert.deepEqual(humanReport({ ...HUMAN, ...real(1.25) }, edge).notes, ['pointer:mouse', 'moves:9', 'grid:1.00']);
  const scripted = { dpr: 1.25, points: Array.from({ length: 20 }, (_, i) => [298.2966 + i * 31.0137, 210.4419 + i * 7.31]) };
  assert.deepEqual(humanReport({ ...HUMAN, ...scripted }, edge).notes, ['off_grid_pointer', 'pointer:mouse', 'moves:9', 'grid:0.00']);
  // Whole numbers at a 125% display are a script that rounded its coordinates: only a quarter land on the grid.
  const rounded = { dpr: 1.25, heights: [797, 706], points: Array.from({ length: 20 }, (_, i) => [300 + i + 0.6, 400.6]) };
  assert.equal(humanReport({ ...HUMAN, ...rounded }, edge).automated, true);
  // On the grid of a 250% display zoomed out to 50%: allowed only when the window could hold such a page.
  const half = { ...rounded, points: Array.from({ length: 20 }, (_, i) => [301.6 + 2 * i, 401.6]) };
  assert.equal(humanReport({ ...HUMAN, ...half, heights: [797, 1400] }, edge).automated, false);
  assert.equal(humanReport({ ...HUMAN, ...half }, edge).automated, true);
  for (const ua of [firefox, mac]) assert.equal(humanReport({ ...HUMAN, ...scripted }, ua).automated, false, ua);
  for (const bad of [{ dpr: 0 }, { dpr: '1.25' }, { points: [[1, 2, 3]] }, { points: 'x' }, { ...scripted, points: scripted.points.slice(0, 9) }]) {
    assert.equal(humanReport({ ...HUMAN, ...scripted, ...bad }, edge).automated, false, JSON.stringify(bad).slice(0, 40));
  }
  // The DevTools protocol's touch emulation on a PC without a touchscreen, or on a Mac. Real touchscreens report 5+.
  const touch = { ...HUMAN, pointer: 'touch', path: [], pressGap: -1 };
  assert.deepEqual(humanReport({ ...touch, env: { touch: 1 } }, edge).notes.slice(0, 1), ['emulated_touch']);
  assert.equal(humanReport({ ...touch, env: { touch: 0 } }, mac).automated, true);
  assert.equal(humanReport({ ...touch, env: { touch: 10 } }, edge).automated, false);
  assert.equal(humanReport({ ...touch, env: { touch: 5 } }, 'Mozilla/5.0 (Linux; Android 15) Chrome/141.0 Mobile Safari/537.36').automated, false);
  assert.equal(humanReport({ ...touch, env: { touch: 1 } }, 'Mozilla/5.0 (Linux; Android 15) Chrome/141.0 Mobile Safari/537.36').automated, false);
  // A key held on Windows repeats; one keydown and a wait does not. People with repeat off are told to use the pointer.
  const keyboard = { ...HUMAN, pointer: 'keyboard', path: [], pressGap: -1 };
  assert.equal(humanReport({ ...keyboard, repeats: 14 }, edge).unrepeated, false);
  assert.deepEqual(humanReport({ ...keyboard, repeats: 0 }, firefox).notes, ['no_key_repeat', 'pointer:keyboard', 'moves:0', 'repeats:0']);
  assert.equal(humanReport({ ...keyboard, repeats: 'many' }, edge).unrepeated, true);
  assert.equal(humanReport({ ...keyboard, repeats: 0 }, mac).unrepeated, false); // A Mac's longest repeat delay is longer than the hold.
  assert.equal(humanReport({ ...keyboard, repeats: 0, holdMs: 900 }, edge).unrepeated, false); // Too short to judge; fails the hold anyway.
  const f = await fixture(t);
  const cases = [
    [{ input: [40, 0] }, 'automation_detected'],
    [{ ...scripted, input: [40, 38] }, 'automation_detected'],
    [{ ...touch, env: { touch: 1 } }, 'automation_detected'],
    [{ ...keyboard, repeats: 0 }, 'human_check_failed'],
  ];
  for (const [index, [signals, reason]] of cases.entries()) {
    const headers = visitor(`203.0.113.${200 + index}`, { 'user-agent': edge });
    const response = await check(f, { headers, signals });
    assert.equal(response.status, 403); assert.equal(await errorOf(response), reason);
  }
  for (const [index, signals] of [{ input: [52, 45] }, { ...keyboard, repeats: 14 }, { ...touch, env: { touch: 10 } }].entries()) {
    const response = await check(f, { headers: visitor(`203.0.113.${210 + index}`, { 'user-agent': edge }), signals });
    assert.equal(response.status, 200, await response.clone().text());
  }
});

test('requests held by a DevTools client are caught: cached fetches from the page cost far more than from a shared worker', async t => {
  const edge = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0';
  const mac = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
  // Measured [page ms, shared worker ms, fetches]: Edge, Chrome, an extension watching requests, load, DevTools open.
  for (const fetches of [[5.2, 4.8, 10], [4.9, 4, 10], [11, 10, 10], [7.2, 6.2, 10], [8.3, 5.6, 10], [0.9, 0.3, 8]]) {
    assert.equal(humanReport({ ...HUMAN, fetches }, edge).automated, false, String(fetches));
  }
  // patchright, which intercepts every request: 2.6 to 3.4 times, and at least 0.65 ms more per fetch.
  assert.deepEqual(humanReport({ ...HUMAN, fetches: [10.6, 4, 10] }, edge).notes, ['request_interception', 'pointer:mouse', 'moves:9', 'fetches:2.65']);
  assert.equal(humanReport({ ...HUMAN, fetches: [19.2, 5.7, 8] }, edge).automated, true);
  assert.equal(humanReport({ ...HUMAN, fetches: [10.6, 4, 10] }, mac).automated, false); // Not measured off Windows.
  for (const fetches of [[10.6, 0, 10], [10.6, 4], [10.6, 4, 2], [10.6, 4, 7.5], ['10.6', 4, 10], null]) {
    assert.equal(humanReport({ ...HUMAN, fetches }, edge).automated, false, JSON.stringify(fetches));
  }
  const f = await fixture(t);
  // The byte the page times stays in the browser's cache; the shared worker that times it from outside the page.
  const cached = await f.request('/_gate/human/cached?123456', { headers: visitor() });
  assert.equal(cached.status, 200); assert.equal(cached.headers.get('cache-control'), 'private, max-age=600'); assert.equal(await cached.text(), '1');
  assert.match(readFileSync(new URL('../web/shared.js', import.meta.url), 'utf8'), /onconnect[\s\S]*transferSize === 0/);
  const response = await check(f, { headers: visitor('203.0.113.220', { 'user-agent': edge }), signals: { fetches: [10.6, 4, 10] } });
  assert.equal(response.status, 403); assert.equal(await errorOf(response), 'automation_detected');
  const passed = await check(f, { headers: visitor('203.0.113.221', { 'user-agent': edge }), signals: { fetches: [5.2, 4.8, 10] } });
  assert.equal(passed.status, 200, await passed.clone().text());
});

test('each check gets its own scrambled script, and only that script can seal a report the server accepts', async t => {
  const f = await fixture(t);
  const issued = await f.post('/_gate/human/options', {}, null, visitor());
  const cookie = f.cookieOf(issued);
  const script = await f.request('/_gate/human/probe.js', { headers: { ...visitor(), cookie } });
  assert.equal(script.status, 200); assert.match(script.headers.get('content-type'), /javascript/); assert.equal(script.headers.get('cache-control'), 'no-store');
  const source = await script.text();
  // Nothing to find by name: no API names, no report fields, and the key only in encoded form.
  for (const word of ['console', 'debug', 'webdriver', 'devtools', 'performance', 'navigator', 'native code', 'hooked', probeKey(f, cookie)]) assert.ok(!source.includes(word), word);
  const worker = await f.request('/_gate/human/probe-worker.js', { headers: { ...visitor(), cookie } });
  assert.equal(worker.status, 200); assert.match(worker.headers.get('content-type'), /javascript/);
  const workerSource = await worker.text();
  for (const word of ['console', 'debug', 'devtools', 'performance', f.store.peekChallenge(cookie.split('=')[1]).probe.workerKey]) assert.ok(!workerSource.includes(word), word);
  assert.equal((await f.request('/_gate/human/probe-worker.js', { headers: visitor() })).status, 404);
  const other = scrambledProbe();
  assert.notEqual(other.source, scrambledProbe().source); assert.notEqual(other.key, scrambledProbe().key);
  // Without this check's cookie, or from another client, there is no script.
  assert.equal((await f.request('/_gate/human/probe.js', { headers: visitor() })).status, 404);
  assert.equal((await f.request('/_gate/human/probe.js', { headers: { ...visitor(), cookie, 'user-agent': 'other' } })).status, 404);
  // A report rewritten in transit, sealed with another check's key, or sent in the old plain form is refused as tampering.
  const genuine = sealReport({ ...HUMAN, devtools: 5.1 }, '00'.repeat(32));
  for (const [index, report] of [genuine, genuine.replace(/^./, c => (c === 'A' ? 'B' : 'A')), undefined, 'x.y', 42].entries()) {
    const response = await check(f, { headers: visitor(`203.0.113.${60 + index}`), report: report ?? '' });
    assert.equal(response.status, 403); assert.equal(await errorOf(response), 'automation_detected');
    assert.ok(f.audit.at(-1).automationSignals.includes('report_tampered'));
  }
  assert.deepEqual(openReport(sealReport({ a: 1 }, 'ab'.repeat(32)), 'ab'.repeat(32)), { a: 1 });
  for (const [text, key] of [[sealReport([1], 'ab'.repeat(32)), 'ab'.repeat(32)], ['', 'ab'.repeat(32)], ['a.b.c', 'ab'.repeat(32)], ['x.y', 'short'], [null, null]]) assert.equal(openReport(text, key), null);
  // Functions replaced to hide automation are reported by the script itself.
  const hooked = await check(f, { headers: visitor('203.0.113.70'), signals: { hooked: true } });
  assert.equal(await errorOf(hooked), 'automation_detected');
  assert.ok(f.audit.at(-1).automationSignals.includes('console_tampered'));
});

test('the worker repeats the timing where page hooks cannot reach, and must answer', async t => {
  const f = await fixture(t);
  const chrome = { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0) Chrome/141.0 Safari/537.36' };
  const run = async (address, devtools, worker) => {
    const headers = visitor(address, chrome);
    const issued = await f.post('/_gate/human/options', {}, null, headers);
    const { challenge, difficulty } = await issued.json();
    f.advance(1600);
    const cookie = f.cookieOf(issued), probe = f.store.peekChallenge(cookie.split('=')[1]).probe;
    const sealed = worker === undefined ? undefined : typeof worker === 'string' ? worker : sealReport({ devtools: worker }, probe.workerKey);
    const response = await f.post('/_gate/human/verify', { nonce: solve(challenge, difficulty), report: sealReport({ ...HUMAN, devtools, worker: sealed }, probe.key) }, cookie, headers);
    return [response.status, f.audit.at(-1).automationSignals ?? []];
  };
  assert.equal((await run('203.0.113.80', 1.3, 1.2))[0], 200);
  // A page hook flattened the page's timing, but the worker still sees the attached client.
  const [hidden, hiddenSignals] = await run('203.0.113.81', 1.04, 4.58);
  assert.equal(hidden, 403); assert.ok(hiddenSignals.includes('devtools_protocol'));
  // The page measured but the worker never answered, or its report was forged.
  for (const [index, worker] of [undefined, 'x.y', sealReport({ devtools: 1.2 }, '00'.repeat(32))].entries()) {
    const [status, signals] = await run(`203.0.113.${82 + index}`, 1.3, worker);
    assert.equal(status, 403); assert.ok(signals.includes('console_tampered'), String(worker));
  }
});

test('a pass covers a reading session, not a whole site', async t => {
  const f = await fixture(t, { humanPagesPerPass: 3, humanPagesPerMinute: 100 });
  const passed = await check(f);
  const cookie = f.cookieOf(passed);
  for (let i = 1; i <= 3; i++) assert.equal((await get(f, `/article/${i}`, visitor('203.0.113.10', { ...page, cookie }))).status, 200);
  assert.equal((await get(f, '/article/4', visitor('203.0.113.10', { ...page, cookie }))).status, 403);
  assert.equal(f.audit.at(-1).reason, 'human_recheck');
});

test('declared AI agents and signed agents are refused, even before passkey admission', async t => {
  const f = await fixture(t);
  const chatgpt = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot';
  const refused = await get(f, '/', visitor('203.0.113.10', { ...page, 'user-agent': chatgpt }));
  assert.equal(refused.status, 403); assert.match(refused.text, /AI agents are not allowed here/);
  const signed = await f.request('/', { headers: visitor('203.0.113.11', { 'signature-agent': '"https://chatgpt.com"' }) });
  assert.equal(await errorOf(signed), 'ai_agent');
  const options = await f.post('/_gate/human/options', {}, null, visitor('203.0.113.12', { 'user-agent': 'ClaudeBot/1.0' }));
  assert.equal(await errorOf(options), 'ai_agent'); // Cannot even start the check.
  assert.equal((await get(f, '/robots.txt', visitor('203.0.113.10', { 'user-agent': chatgpt }))).status, 200);
  assert.equal(f.audit.find(event => event.reason === 'ai_agent').automationSignals.at(-1), 'ai_agent:user_agent');

  const open = await fixture(t, {}, { AI_AGENTS: 'allow', HUMAN_CHECK: 'off' });
  assert.equal((await get(open, '/', visitor('203.0.113.10', { 'user-agent': chatgpt }))).status, 200);
  const invited = await createFixture({}, undefined, ASSETS, { MODE: 'private' }); t.after(invited.close);
  assert.equal((await invited.request('/', { headers: { 'user-agent': 'Perplexity-User/1.0' } })).status, 403);
  assert.equal(declaredAIAgent({ 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/141.0 Safari/537.36' }), null);
  assert.equal(declaredAIAgent({ 'user-agent': 'GPTBotanist/2.0' }), null);
  // The Claude desktop app's built-in browser names the app; it is an AI agent's browser.
  assert.equal(declaredAIAgent({ 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Claude/2.19675.0 Chrome/152.0.7977.130 Safari/537.36' }), 'ai_browser');
});

test('verified search engines skip the check; a crawler name alone does not', async t => {
  const f = await fixture(t);
  const googlebot = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
  assert.equal((await get(f, '/', visitor('66.249.66.1', { 'user-agent': googlebot }))).status, 200);
  assert.equal((await get(f, '/', visitor('203.0.113.66', { 'user-agent': googlebot }))).status, 403); // Wrong domain.
  assert.equal((await get(f, '/', visitor('198.51.100.7', { 'user-agent': googlebot }))).status, 403); // Does not resolve back.
  assert.equal((await get(f, '/', visitor('66.249.66.1'))).status, 403); // The address alone is not enough either.
  assert.ok(f.audit.some(event => event.automationSignals.includes('crawler:googlebot')));
  const strict = await fixture(t, {}, { VERIFIED_CRAWLERS: 'off' });
  assert.equal((await get(strict, '/', visitor('66.249.66.1', { 'user-agent': googlebot }))).status, 403);
});

test('opening pages faster than a person reads asks again; page assets do not count', async t => {
  const f = await fixture(t, { humanPagesPerMinute: 3 });
  const cookie = f.cookieOf(await check(f));
  const headers = visitor('203.0.113.10', { cookie });
  for (let i = 0; i < 10; i++) assert.equal((await get(f, `/image-${i}.png`, headers)).status, 200);
  for (let i = 0; i < 3; i++) assert.equal((await get(f, `/page-${i}`, { ...headers, ...page })).status, 200);
  const again = await get(f, '/page-3', { ...headers, ...page });
  assert.equal(again.status, 403); assert.match(again.text, /Still you\?/);
  assert.match((await get(f, '/page-4', { ...headers, ...page })).text, /Confirm you are human/); // The old pass is gone.
});

test('each network can earn only so many passes an hour', async t => {
  const f = await fixture(t, { humanPassesPerHour: 2 });
  assert.equal((await check(f)).status, 200);
  assert.equal((await check(f)).status, 200);
  const third = await check(f);
  assert.equal(third.status, 429); assert.equal(await errorOf(third), 'human_check_limit');
  assert.equal((await check(f, { headers: visitor('198.51.100.30') })).status, 200);
});

test('unban also clears the counters that caused the block', () => {
  const store = new Store(':memory:');
  for (const key of ['strike:n1', 'all:n1', 'reader:network:n1']) { store.limit(key, 1); assert.equal(store.limit(key, 1), false); }
  store.ban('n1', 60, 600);
  assert.equal(store.unban('n1'), true);
  for (const key of ['strike:n1', 'all:n1', 'reader:network:n1']) assert.equal(store.limit(key, 1), true);
  assert.equal(store.banned('n1'), undefined);
  store.close();
});

// Field-measured environments (see docs/threat-model.md). A real Windows laptop in Edge:
const WINDOWS = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
const LAPTOP = { webgl: true, gpu: 'ANGLE (NVIDIA, NVIDIA GeForce RTX 5060 Laptop GPU (0x00002D59) Direct3D11 vs_5_0 ps_5_0, D3D11)', glNative: true, render: 'c60b13631bac3fc2',
  fonts: ['Segoe UI', 'Calibri', 'Consolas'], voices: 3, media: 3, touch: 0, screen: [1536, 864, 1536, 816], tz: 'Asia/Calcutta' };
// Chrome on a Linux cloud server under a virtual display.
const SERVER = { webgl: true, gpu: 'ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)', glNative: true, render: '6cf4933af807630f',
  fonts: [], voices: 0, media: 0, touch: 0, screen: [1280, 720, 1280, 720], tz: 'UTC' };
const LINUX = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';

test('cloud ranges merge, match both IP versions, and reject malformed lines', () => {
  const ranges = cloudRanges(['# comment', '203.0.113.0/25', '203.0.113.128/25 # adjacent', '198.51.100.7', '2001:db8::/32', '']);
  assert.equal(ranges.size, 3); // The two halves merge into one /24.
  for (const ip of ['203.0.113.0', '203.0.113.255', '198.51.100.7', '::ffff:203.0.113.9', '2001:db8:ffff::1']) assert.equal(ranges.has(ip), true, ip);
  for (const ip of ['203.0.114.0', '198.51.100.8', '2001:db9::1', 'not-an-ip']) assert.equal(ranges.has(ip), false, ip);
  assert.throws(() => cloudRanges(['10.0.0.0/33']), /Invalid cloud range/);
});

test('sandbox signals score servers high and real personal devices at zero', () => {
  assert.deepEqual(sandboxReport(LAPTOP, WINDOWS), { score: 0, found: [], notes: ['sandbox:0'] });
  const server = sandboxReport(SERVER, LINUX, { datacenter: true });
  assert.deepEqual(server.found, ['datacenter', 'software_gpu', 'no_media_devices', 'bare_screen', 'utc_clock']); // Linux voices are not judged.
  assert.equal(server.score, 7);
  // The same server claiming to be Windows: no Windows fonts and no voices give it away even off a datacenter address.
  assert.deepEqual(sandboxReport(SERVER, WINDOWS).found, ['software_gpu', 'os_mismatch', 'no_voices', 'no_media_devices', 'bare_screen', 'utc_clock']);
  // A faked GPU name: the pixels are still SwiftShader's, or the getter is patched.
  assert.deepEqual(sandboxReport({ ...LAPTOP, render: '6cf4933af807630f' }, WINDOWS).found, ['gpu_spoofed']);
  assert.deepEqual(sandboxReport({ ...LAPTOP, glNative: false }, WINDOWS).found, ['gpu_spoofed']);
  assert.deepEqual(sandboxReport({ ...LAPTOP, gpu: 'VMware SVGA 3D' }, WINDOWS).found, ['virtual_gpu']);
  // A person on a VPN that exits from a datacenter is flagged, but only enough for a shorter pass.
  assert.equal(sandboxReport(LAPTOP, WINDOWS, { datacenter: true }).score, 2);
  // iPads send a Mac user agent; touch points mean the desktop checks do not apply.
  const iPad = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15';
  assert.equal(sandboxReport({ ...LAPTOP, gpu: 'Apple GPU', fonts: [], touch: 5, screen: [1024, 1366, 1024, 1366] }, iPad).score, 0);
  // Playwright's bundled Chromium names no vendor. On Windows and Mac people use branded browsers; on Linux many do not.
  assert.deepEqual(sandboxReport(LAPTOP, WINDOWS, { brands: 'Chromium|Not_A Brand' }).found, ['unbranded_browser']);
  assert.equal(sandboxReport(LAPTOP, WINDOWS, { brands: 'Chromium|Not_A Brand' }).score, 3);
  for (const brands of ['Chromium|Google Chrome|Not=A?Brand', 'Chromium|Microsoft Edge|Not A(Brand', 'Brave|Chromium|Not/A)Brand', '', 7]) assert.equal(sandboxReport(LAPTOP, WINDOWS, { brands }).score, 0);
  assert.equal(sandboxReport(LAPTOP, LINUX, { brands: 'Chromium|Not_A Brand' }).score, 0);
  assert.equal(unbrandedChromium(['Not)A;Brand', 'Chromium']), true);
  assert.equal(unbrandedChromium([]), false);
  // Malformed or missing reports count for nothing; the other checks still apply.
  for (const env of [undefined, null, [], 'x', { gpu: 7, fonts: 'Segoe UI', voices: -1, screen: [1, 2], tz: 5 }]) assert.equal(sandboxReport(env, WINDOWS).score, 0);
});

test('sandbox scores are only recorded in log mode, and refuse or shorten passes in enforce mode', async t => {
  const cloud = cloudRanges(['198.51.100.0/24']);
  const server = { 'x-forwarded-for': '198.51.100.9', 'user-agent': LINUX };
  const logged = await fixture(t, { cloud }, { SANDBOX_CHECK: 'log' });
  const allowed = await check(logged, { signals: { env: SERVER }, headers: server });
  assert.equal(allowed.status, 200);
  assert.deepEqual(logged.audit.find(event => event.reason === 'human_pass_issued').automationSignals.slice(-6),
    ['datacenter', 'software_gpu', 'no_media_devices', 'bare_screen', 'utc_clock', 'sandbox:7']);

  const f = await fixture(t, { cloud }); // enforce is the default
  const refused = await check(f, { signals: { env: SERVER }, headers: server });
  assert.equal(refused.status, 403); assert.equal(await errorOf(refused), 'sandbox_detected');
  // A real laptop behind a datacenter VPN: allowed, but the pass lasts an hour.
  const vpn = await check(f, { signals: { env: LAPTOP }, headers: { 'x-forwarded-for': '198.51.100.10', 'user-agent': WINDOWS } });
  assert.equal(vpn.status, 200); assert.match(vpn.headers.get('set-cookie'), /Max-Age=3600/);
  const home = await check(f, { signals: { env: LAPTOP }, headers: { 'x-forwarded-for': '203.0.113.10', 'user-agent': WINDOWS } });
  assert.equal(home.status, 200); assert.match(home.headers.get('set-cookie'), /Max-Age=21600/);

  const off = await fixture(t, { cloud }, { SANDBOX_CHECK: 'off' });
  assert.equal((await check(off, { signals: { env: SERVER }, headers: server })).status, 200);
  assert.ok(!off.audit.find(event => event.reason === 'human_pass_issued').automationSignals.some(note => note.startsWith('sandbox')));
});

// What Chrome on Windows sends for a page load.
const CHROME = { 'user-agent': WINDOWS, accept: 'text/html,application/xhtml+xml', 'accept-language': 'en-IN,en;q=0.9', 'sec-fetch-mode': 'navigate',
  'sec-fetch-dest': 'document', 'sec-fetch-site': 'none', 'sec-ch-ua': '"Chromium";v="141", "Google Chrome";v="141"' };
const suspicious = (t, overrides = {}, env = {}) => fixture(t, overrides, { HUMAN_CHECK: 'suspicious', ...env });
const lastReason = f => f.audit.at(-1).automationSignals.find(note => note.startsWith('suspect:'));

test('in suspicious mode a person in an ordinary browser never sees the check', async t => {
  const f = await suspicious(t);
  for (const path of ['/', '/article/1', '/article/2']) assert.equal((await get(f, path, visitor('203.0.113.10', CHROME))).text, 'PRIVATE_ORIGIN_CONTENT');
  // Images and scripts carry no language header in some browsers, and are not page loads.
  const image = { ...CHROME, accept: 'image/avif,image/webp', 'sec-fetch-dest': 'image', 'sec-fetch-mode': 'no-cors', 'accept-language': undefined };
  delete image['accept-language'];
  assert.equal((await get(f, '/logo.png', visitor('203.0.113.10', image))).status, 200);
  // Browsers that legitimately send fewer headers: Firefox (no client hints), Android in-app browsers, older Safari.
  const firefox = { ...CHROME, 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0' }; delete firefox['sec-ch-ua'];
  const webview = { ...firefox, 'user-agent': 'Mozilla/5.0 (Linux; Android 15; Pixel 9; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/141.0.0.0 Mobile Safari/537.36' };
  const safari = { 'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Mobile/15E148 Safari/604.1', accept: 'text/html', 'accept-language': 'en-GB' };
  for (const headers of [firefox, webview, safari]) assert.equal((await get(f, '/article/3', visitor('203.0.113.11', headers))).status, 200, headers['user-agent']);
});

test('in suspicious mode scripts, automation, odd headers and datacenter addresses get the check', async t => {
  const f = await suspicious(t, { cloud: cloudRanges(['198.51.100.0/24']) });
  const cases = [
    [{ 'user-agent': 'curl/8.9.1', accept: '*/*' }, 'not_a_browser'],
    [{ 'user-agent': 'python-requests/2.32.3' }, 'not_a_browser'],
    // A script borrowing Chrome's name. Node's fetch adds Fetch Metadata itself, so the missing client hints give it away.
    [{ 'user-agent': WINDOWS, accept: 'text/html', 'accept-language': 'en' }, 'missing_client_hints'],
    [{ ...CHROME, 'sec-ch-ua': undefined }, 'missing_client_hints'],
    [{ ...CHROME, 'accept-language': undefined }, 'missing_language'],
    [{ ...CHROME, 'user-agent': WINDOWS.replace('Chrome/', 'HeadlessChrome/') }, 'automation_user_agent'],
    // Playwright's own Chromium, even with every other header right.
    [{ ...CHROME, 'sec-ch-ua': '"Chromium";v="141", "Not_A Brand";v="24"' }, 'unbranded_chromium'],
  ];
  for (const [headers, reason] of cases) {
    for (const key of Object.keys(headers)) if (headers[key] === undefined) delete headers[key];
    const response = await get(f, '/article/1', visitor('203.0.113.20', headers));
    assert.equal(response.status, 403, reason); assert.equal(lastReason(f), `suspect:${reason}`);
  }
  assert.equal((await get(f, '/article/1', visitor('198.51.100.9', CHROME))).status, 403);
  assert.equal(lastReason(f), 'suspect:datacenter');
  // Unbranded Chromium on Linux or Android is common among people and is not asked.
  assert.equal(headerAnomaly({ ...CHROME, 'user-agent': LINUX, 'sec-ch-ua': '"Chromium";v="141", "Not_A Brand";v="24"' }, { document: true }), null);
  // Python and Go HTTP clients send no Fetch Metadata at all.
  assert.equal(headerAnomaly({ 'user-agent': WINDOWS, 'accept-language': 'en' }, { document: true }), 'missing_fetch_metadata');
  // The page they get is the check, and passing it lets them read.
  const html = await get(f, '/article/1', visitor('203.0.113.21', { 'user-agent': 'curl/8.9.1', accept: 'text/html' }));
  assert.match(html.text, /Confirm you are human/);
  const passed = await check(f, { headers: visitor('198.51.100.9', CHROME) });
  assert.equal(passed.status, 200);
  assert.equal((await get(f, '/article/1', visitor('198.51.100.9', { ...CHROME, cookie: f.cookieOf(passed) }))).status, 200);
});

test('in suspicious mode fast paging or a failed check makes the whole network confirm for an hour', async t => {
  const f = await suspicious(t, {}, { HUMAN_PAGES_PER_MINUTE: '5' });
  for (let i = 0; i < 5; i++) assert.equal((await get(f, `/article/${i}`, visitor('203.0.113.30', CHROME))).status, 200);
  assert.equal((await get(f, '/article/5', visitor('203.0.113.30', CHROME))).status, 403);
  assert.equal(lastReason(f), 'suspect:paging');
  f.advance(61000); // A new minute does not lift it.
  assert.equal((await get(f, '/article/6', visitor('203.0.113.30', CHROME))).status, 403);
  assert.equal(lastReason(f), 'suspect:flagged');
  f.advance(3600000);
  assert.equal((await get(f, '/article/7', visitor('203.0.113.30', CHROME))).status, 200);
  // A browser that fails the check cannot then slip through with clean-looking plain requests.
  const failed = await check(f, { signals: { webdriver: true }, headers: visitor('203.0.113.31', CHROME) });
  assert.equal(await errorOf(failed), 'automation_detected');
  assert.equal((await get(f, '/article/1', visitor('203.0.113.31', CHROME))).status, 403);
  assert.equal(lastReason(f), 'suspect:flagged');
});

test('open paths skip the check for feeds and similar files, and settings are validated', async t => {
  const f = await suspicious(t, {}, { OPEN_PATHS: '/robots.txt,/feed.xml' });
  assert.equal((await get(f, '/feed.xml', visitor('203.0.113.40', { 'user-agent': 'FeedReader/3.1' }))).status, 200);
  assert.equal((await get(f, '/other.xml', visitor('203.0.113.40', { 'user-agent': 'FeedReader/3.1' }))).status, 403);
  const { configFromEnv } = await import('../src/config.mjs');
  assert.equal(configFromEnv({}).humanCheck, 'suspicious');
  assert.throws(() => configFromEnv({ HUMAN_CHECK: 'sometimes' }), /HUMAN_CHECK/);
  assert.throws(() => configFromEnv({ OPEN_PATHS: 'feed.xml' }), /OPEN_PATHS/);
});

// Desktop Firefox, and the check page's own step to the hop page: a same-origin navigation of this tab.
const FIREFOX = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0';
const LOAD = { accept: 'text/html', 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' };
const hopID = () => randomBytes(32).toString('base64url');
// Node's fetch adds Fetch Metadata of its own, so page loads go out exactly as a browser sends them.
function navigate(f, path, headers) {
  return new Promise((resolve, reject) => {
    http.get(`${f.config.origin}${path}`, { headers }, res => {
      let text = ''; res.setEncoding('utf8');
      res.on('data', chunk => { text += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text, cookie: res.headers['set-cookie']?.[0].split(';')[0] }));
    }).on('error', reject);
  });
}
const hopTo = (f, id, to, headers) => navigate(f, `/_gate/human/hop?id=${id}&to=${encodeURIComponent(to)}`, { ...LOAD, ...headers });

test('Firefox has to come back from the hop page without loading the check again', async t => {
  const f = await fixture(t);
  const firefox = visitor('203.0.113.50', { 'user-agent': FIREFOX });
  const shown = await navigate(f, '/article?id=7', { ...firefox, ...LOAD, 'sec-fetch-site': 'none' });
  assert.equal(shown.status, 403); assert.match(shown.text, /Confirm you are human/);
  // Firefox keeps a page for the Back button only if it may be stored, and only away from a page that opened it.
  assert.equal(shown.headers['cache-control'], 'private, no-cache');
  assert.equal(shown.headers['cross-origin-opener-policy'], 'same-origin');
  // And a stored copy is never reused, so a browser without that cache has to ask the gateway again.
  assert.equal(shown.headers.vary, '*');
  // Camoufox as shipped: no trip made, or the trip's page loaded again, so no hop to show.
  const skipped = await check(f, { headers: firefox });
  assert.equal(await errorOf(skipped), 'automation_detected');
  assert.ok(f.audit.at(-1).automationSignals.includes('no_back_forward_cache'));

  const person = visitor('198.51.100.51', { 'user-agent': FIREFOX });
  const id = hopID();
  const stepped = await hopTo(f, id, '/article?id=7', person);
  assert.equal(stepped.status, 200);
  assert.match(stepped.text, /\/_gate\/hop\.js/);
  assert.match(stepped.headers['set-cookie'][0], new RegExp(`^hg_hop=${id}; Path=/; HttpOnly; SameSite=Strict; Max-Age=60`));
  assert.equal(stepped.headers['cache-control'], 'no-store, private');
  assert.equal(stepped.headers['cross-origin-opener-policy'], 'same-origin');
  const passed = await check(f, { headers: person, hop: id });
  assert.equal(passed.status, 200, await passed.clone().text());
  // Each trip counts once, and only for the browser that made it.
  assert.equal(await errorOf(await check(f, { headers: person, hop: id })), 'automation_detected');
  const other = hopID();
  assert.equal((await hopTo(f, other, '/', person)).status, 200);
  assert.equal(await errorOf(await check(f, { headers: visitor('198.51.100.51', { 'user-agent': `${FIREFOX} Other` }), hop: other })), 'automation_detected');
  // Other browsers do not make the trip.
  assert.equal((await check(f, { headers: visitor('192.0.2.52', CHROME) })).status, 200);
});

test('a check page loaded again straight after its hop is refused as automation', async t => {
  const f = await fixture(t);
  const firefox = visitor('203.0.113.60', { 'user-agent': FIREFOX });
  const { cookie } = await hopTo(f, hopID(), '/article?id=7', firefox);
  assert.ok(cookie);
  // Another page, or a request that is not a page load, is just a new check.
  assert.match((await navigate(f, '/other', { ...firefox, ...LOAD, cookie })).text, /Confirm you are human/);
  assert.equal(await errorOf(await f.request('/article?id=7', { headers: { ...firefox, cookie } })), 'human_check_required');
  const reloaded = await navigate(f, '/article?id=7', { ...firefox, ...LOAD, cookie });
  assert.equal(reloaded.status, 403);
  assert.match(reloaded.text, /Automated browser detected[\s\S]*Back button/);
  assert.match(reloaded.headers['set-cookie'][0], /^hg_hop=; .*Max-Age=0/);
  assert.equal(f.audit.at(-1).reason, 'automation_detected');
  assert.deepEqual(f.audit.at(-1).automationSignals, ['back_forward_reload']);
  // Used up: loading it again is a new check.
  assert.match((await navigate(f, '/article?id=7', { ...firefox, ...LOAD, cookie })).text, /Confirm you are human/);
  // So is the same page a while later.
  const late = await hopTo(f, hopID(), '/late', firefox);
  f.advance(15001);
  assert.match((await navigate(f, '/late', { ...firefox, ...LOAD, cookie: late.cookie })).text, /Confirm you are human/);
  // Another browser's cookie does not get this one refused.
  const theirs = await hopTo(f, hopID(), '/mine', firefox);
  assert.match((await navigate(f, '/mine', { ...visitor('203.0.113.60', { 'user-agent': `${FIREFOX} Other` }), ...LOAD, cookie: theirs.cookie })).text, /Confirm you are human/);
});

test('Firefox moves made through Juggler are caught on Windows: they reach the page as soon as they are stamped', async t => {
  // Milliseconds from each move's time stamp to the page's handler, measured in Firefox 157 on Windows.
  const hand = [1, 1, 15, 6, 1, 15, 6, 6, 14, 11, 9, 16, 9, 16, 14, 4, 12, 11, 6, 14, 7, 4, 15, 11, 4, 0, 10, 3, 14, 9, 0, 10, 5, 2, 14, 9, 7, 14, 12, 2, 14, 11, 6, 16, 6, 3, 23];
  const slow = [7, 15, 8, 2, 9, 3, 11, 3, 12, 5, 13, 7, 16, 8, 17, 9, 1, 10, 3, 12, 5, 13, 16, 8, 0, 9, 3, 10, 4, 13, 4, 14, 7, 15, 7, 1, 10, 2, 11, 3, 11, 5, 13, 6, 15, 7, 2, 11, 2, 11, 4, 13, 5, 13, 6, 13, 7, 16, 7, 1, 9, 4, 13, 15];
  const jumps = [7, 11, 13, 6, 7, 5, 1, 3, 4, 6, 14, 0, 2, 5, 11, 15, 0, 2, 12, 12, 0, 10]; // The cursor set every 50 ms.
  const onTick = [0, 10, 8, 7, 14, 11, 8, 8, 13, 10, 10, 6, 8, 8, 6, 6, 7, 7, 6, 6, 7, 5, 5, 6, 5, 4, 5, 4, 4, 4, 4, 4, 3, 2, 3, 3, 5, 5, 4, 5, 5, 3, 5, 4, 4, 3, 2, 2, 2, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 12];
  // Playwright's Firefox, headed and headless, without pauses.
  const headed = [1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 2, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 2, 1, 1, 0, 1, 0, 0];
  const headless = [5, 6, 5, 5, 5, 6, 6, 6, 5, 6, 6, 6, 5, 6, 6, 5, 5, 5, 7, 5, 5, 5, 5, 5, 6, 5, 6, 5, 5, 6, 6, 5, 5, 6, 5, 5, 6, 5];
  const firefox = { ...HUMAN, brands: '', engine: 'gecko', clock: 1 };
  for (const lags of [hand, slow, jumps, onTick]) assert.equal(humanReport({ ...firefox, lags }, FIREFOX).automated, false, String(lags));
  assert.deepEqual(humanReport({ ...firefox, lags: headed }, FIREFOX).notes, ['synthetic_event_time', 'pointer:mouse', 'moves:9', 'lag-spread:1/38']);
  assert.equal(humanReport({ ...firefox, lags: headless }, FIREFOX).automated, true);
  assert.equal(humanReport({ ...firefox, lags: headless.slice(0, 15) }, FIREFOX).automated, false); // Too few moves to judge.
  // Not judged where real moves carry exact times, on a coarsened clock, for Chromium, or for other pointers.
  const mac = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:143.0) Gecko/20100101 Firefox/143.0';
  assert.equal(humanReport({ ...firefox, lags: headed }, mac).automated, false);
  for (const clock of [16.667, 100, null, 0]) assert.equal(humanReport({ ...firefox, lags: headed, clock }, FIREFOX).automated, false, String(clock));
  assert.equal(humanReport({ ...HUMAN, lags: headed, clock: 0.005 }, WINDOWS).automated, false);
  assert.equal(humanReport({ ...firefox, lags: headed, pointer: 'touch' }, FIREFOX).automated, false);
  // The engine decides, not the name: Firefox claiming to be Chrome on Windows is judged too.
  assert.equal(humanReport({ ...firefox, lags: headed }, WINDOWS).automated, true);
  assert.equal(humanReport({ ...firefox, lags: [...headed.slice(0, 10), 'x', null, -5, ...headed.slice(10)] }, FIREFOX).notes.at(-1), 'lag-spread:1/38');

  const f = await fixture(t);
  const id = hopID(), scripted = visitor('203.0.113.80', { 'user-agent': FIREFOX });
  assert.equal((await hopTo(f, id, '/', scripted)).status, 200);
  const refused = await check(f, { headers: scripted, hop: id, signals: { brands: '', engine: 'gecko', clock: 1, lags: headed } });
  assert.equal(await errorOf(refused), 'automation_detected');
  assert.ok(f.audit.at(-1).automationSignals.includes('synthetic_event_time'));
  const other = hopID(), person = visitor('198.51.100.81', { 'user-agent': FIREFOX });
  assert.equal((await hopTo(f, other, '/', person)).status, 200);
  const passed = await check(f, { headers: person, hop: other, signals: { brands: '', engine: 'gecko', clock: 1, lags: hand } });
  assert.equal(passed.status, 200, await passed.clone().text());
});

test('Chromium launched by automation tools is caught: it lifts the limit on history changes', async t => {
  const chromium = { ...HUMAN, engine: 'chromium' };
  // How many of the probe's 240 changes took effect: Edge and Chrome opened normally (also with a debugging port), 200.
  for (const history of [200, 199, 0, null, undefined, -1, 240.5, '240']) {
    assert.equal(humanReport({ ...chromium, history }, WINDOWS).automated, false, String(history));
  }
  // Playwright on installed Edge or Chrome, headed or headless: all 240.
  assert.deepEqual(humanReport({ ...chromium, history: 240 }, WINDOWS).notes, ['no_navigation_limit', 'pointer:mouse', 'moves:9', 'history:240']);
  assert.equal(humanReport({ ...chromium, history: 240, pointer: 'keyboard', repeats: 30 }, WINDOWS).automated, true); // Any input.
  const mac = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
  assert.equal(humanReport({ ...chromium, history: 240 }, mac).automated, true); // Not a Windows measurement.
  // Chromium claiming to be Firefox is judged; Firefox stops at 199 by itself and is not.
  assert.equal(humanReport({ ...chromium, brands: '', history: 240 }, FIREFOX).automated, true);
  assert.equal(humanReport({ ...HUMAN, brands: '', engine: 'gecko', history: 199 }, FIREFOX).notes.some(note => note.startsWith('history:')), false);

  const f = await fixture(t);
  const refused = await check(f, { headers: visitor('203.0.113.230', { 'user-agent': WINDOWS }), signals: { engine: 'chromium', history: 240 } });
  assert.equal(await errorOf(refused), 'automation_detected');
  assert.ok(f.audit.at(-1).automationSignals.includes('no_navigation_limit'));
  const passed = await check(f, { headers: visitor('198.51.100.231', { 'user-agent': WINDOWS }), signals: { engine: 'chromium', history: 200 } });
  assert.equal(passed.status, 200, await passed.clone().text());
});

test('the hop page takes only the check page’s own step', async t => {
  const f = await fixture(t);
  const firefox = visitor('203.0.113.70', { 'user-agent': FIREFOX });
  const id = hopID();
  // A fetch, a frame or a new tab would leave the check page where it was.
  for (const extra of [{ 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty' }, { 'sec-fetch-dest': 'iframe' }, { 'sec-fetch-site': 'none' }, { 'sec-fetch-site': 'cross-site' }]) {
    assert.equal((await hopTo(f, id, '/', { ...firefox, ...extra })).status, 403, JSON.stringify(extra));
  }
  assert.equal((await navigate(f, `/_gate/human/hop?id=${id}&to=%2F`, firefox)).status, 403);
  for (const [badID, to] of [['short', '/'], [id, '//evil.example/'], [id, 'https://evil.example/'], [id, '/a b'], [id, `/${'a'.repeat(2048)}`]]) {
    assert.equal((await hopTo(f, badID, to, firefox)).status, 400, to.slice(0, 40));
  }
  assert.equal(f.audit.at(-1).reason, 'invalid_hop');
  assert.equal((await hopTo(f, id, '/', firefox)).status, 200);
  // Coming forward to the hop page again later still goes back, and records nothing new.
  const again = await hopTo(f, id, '/', firefox);
  assert.equal(again.status, 200); assert.equal(again.cookie, undefined);
  assert.equal(f.audit.at(-1).reason, 'human_hop_repeat');
  // Only while the human check is in use.
  const off = await fixture(t, {}, { HUMAN_CHECK: 'off' });
  assert.equal((await hopTo(off, hopID(), '/', firefox)).status, 404);
});

test('which browsers must come back from the hop page', () => {
  const chrome = 'Mozilla/5.0 (Windows NT 10.0) Chrome/141.0 Safari/537.36';
  const android = 'Mozilla/5.0 (Android 15; Mobile; rv:143.0) Gecko/143.0 Firefox/143.0';
  assert.equal(humanReport(HUMAN, FIREFOX).automated, false); // Not judged.
  assert.equal(humanReport(HUMAN, FIREFOX, { returned: true }).automated, false);
  assert.deepEqual(humanReport(HUMAN, FIREFOX, { returned: false }).notes.slice(0, 1), ['no_back_forward_cache']);
  // By engine: Firefox claiming to be Chrome still makes the trip, and Chromium claiming to be Firefox is still timed.
  assert.equal(backForwardRequired({ engine: 'gecko' }, chrome), true);
  assert.equal(humanReport({ ...HUMAN, engine: 'gecko' }, chrome, { returned: false }).automated, true);
  assert.equal(backForwardRequired({ engine: 'chromium' }, FIREFOX), false);
  assert.deepEqual(humanReport({ ...HUMAN, engine: 'chromium', devtools: 4.47 }, FIREFOX, { returned: false }).notes.slice(0, 1), ['devtools_protocol']);
  assert.equal(backForwardRequired({ engine: 'other' }, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15'), false);
  // Firefox on Android phones and on iPhone is not measured.
  assert.equal(backForwardRequired({ engine: 'gecko', env: { touch: 5 } }, android), false);
  assert.equal(backForwardRequired({ engine: 'gecko', env: { touch: 0 } }, android), true);
  assert.equal(backForwardRequired({}, 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) FxiOS/143.0 Mobile/15E148 Safari/605.1.15'), false);
});
