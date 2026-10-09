import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import http from 'node:http';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createFixture } from './fixture.mjs';
import { leadingZeroBits } from '../src/gateway.mjs';
import * as basic from '../src/basic.mjs';
import { loadRules } from '../src/rules.mjs';
import { declaredAIAgent } from '../src/agents.mjs';
import { Store } from '../src/store.mjs';
import { cloudRanges } from '../src/cloud.mjs';
import { probeTemplates, scrambledProbe, sealReport, openReport } from '../src/scramble.mjs';

// These tests run the basic rules (src/basic.mjs). A private rules pack carries its own tests.
const { humanReport, headerAnomaly } = basic;
const ASSETS = { '/_gate/index.html': { body: '<h1>Admission required</h1>', type: 'text/html' } };
// A pointer path onto the button.
const HAND = [[18.4, 6.1, 16], [15.2, 5.5, 17], [12.9, 3.8, 16], [9.1, 3.3, 17], [6.6, 1.2, 16], [3.9, 1.7, 17], [2.1, 0.4, 16], [0.8, 0.3, 17]];
const HUMAN = { webdriver: false, trusted: true, holdMs: 1600, pointer: 'mouse', path: HAND, pressGap: 0, frame: [16, 88], plugins: 5, brands: 'Chromium|Google Chrome' };
const WINDOWS = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
const LINUX = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
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

const audits = [];
async function fixture(t, overrides = {}, env = {}) {
  const f = await createFixture({ challengeDifficulty: 4, resolver, ...overrides }, undefined, ASSETS, { MODE: 'public', TRUSTED_PROXIES: '127.0.0.1', HUMAN_CHECK: 'always', ...env });
  audits.push(f.audit); t.after(f.close); return f;
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
// What the browser was told, and the reason the log keeps for the same request.
const answer = async response => {
  const { error, requestID } = await response.json();
  return { error, reason: audits.flat().find(event => event.requestID === requestID)?.reason };
};

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
  assert.deepEqual(issued.automationSignals, ['platform:other', 'pointer:mouse', 'moves:9', 'sandbox:0']);
  f.advance(21601 * 1000);
  assert.equal((await get(f, '/later', visitor('203.0.113.10', { cookie }))).status, 403); // Passes expire.
});

test('automation is caught even when it performs the hold, a claimed hold must really take time, and the browser is not told which', async t => {
  const f = await fixture(t);
  const cases = [
    [{ signals: { webdriver: true } }, 'automation_detected', 'webdriver'],
    [{ signals: { brands: 'HeadlessChrome|Chromium' } }, 'automation_detected', 'headless'],
    [{ signals: { frame: [0, 0], plugins: 0 }, headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0) Chrome/141.0 Safari/537.36' } }, 'automation_detected', 'headless'],
    [{ signals: { path: [[300, 120, 1]] } }, 'human_check_failed', 'jumped'], // Pressed without moving, like agent click tools.
    [{ signals: { trusted: false } }, 'human_check_failed', 'untrusted'],
    [{ signals: { holdMs: 300 } }, 'human_check_failed', 'short_hold'],
    [{ wait: 200 }, 'human_check_failed', 'short_hold'], // The page claims a hold the server never saw.
  ];
  for (const [index, [options, reason, note]] of cases.entries()) {
    const response = await check(f, { ...options, headers: visitor(`203.0.113.${100 + index}`, options.headers) });
    assert.equal(response.status, 403, reason);
    // Every refusal reads the same to the browser. The log says what happened, for `npm run stats` too.
    assert.deepEqual(await answer(response), { error: 'human_check_failed', reason });
    assert.ok(f.audit.at(-1).automationSignals.includes(note), note);
  }
  // A wrong proof of work, or another client finishing the check, is not the gesture's fault.
  assert.equal(await errorOf(await check(f, { headers: visitor('203.0.113.120'), nonce: 'x' })), 'invalid_solution');
  const other = visitor('203.0.113.121');
  assert.equal(await errorOf(await check(f, { headers: other, verifyHeaders: { ...other, 'user-agent': 'other-client' } })), 'invalid_challenge');
  const report = humanReport({ webdriver: 'yes', holdMs: 'long', path: [[1, 'x', 2], 'junk'], pointer: '<script>', frame: 'none' });
  assert.deepEqual(report, { automated: false, trusted: false, holdMs: 0, jumped: false, unrepeated: false, notes: ['pointer:unknown', 'moves:0'] });
  // Touch and keyboard users never hover, and a frameless phone browser is not headless.
  assert.equal(humanReport({ ...HUMAN, pointer: 'touch', path: [] }).jumped, false);
  assert.equal(humanReport({ ...HUMAN, frame: [0, 0], plugins: 0 }, 'Mozilla/5.0 (Linux; Android 15) Chrome/141.0 Mobile Safari/537.36').automated, false);
  assert.equal((await f.post('/_gate/human/verify', { signals: HUMAN }, null, visitor())).status, 403); // No issued check.
});

test('each check gets its own scrambled script, and only that script can seal a report the server accepts', async t => {
  const f = await fixture(t);
  const issued = await f.post('/_gate/human/options', {}, null, visitor());
  const cookie = f.cookieOf(issued);
  const script = await f.request('/_gate/human/probe.js', { headers: { ...visitor(), cookie } });
  assert.equal(script.status, 200); assert.match(script.headers.get('content-type'), /javascript/); assert.equal(script.headers.get('cache-control'), 'no-store');
  const source = await script.text();
  // Nothing to find by name: no API names, no report fields, no comments, and the key only in encoded form.
  for (const word of ['navigator', 'webdriver', 'userAgentData', 'maxTouchPoints', 'SHA-256', 'checksum', probeKey(f, cookie)]) assert.ok(!source.includes(word), word);
  // The basic rules have no worker script.
  assert.equal((await f.request('/_gate/human/probe-worker.js', { headers: { ...visitor(), cookie } })).status, 404);
  const templates = probeTemplates(basic.probe);
  const other = scrambledProbe(templates);
  assert.notEqual(other.source, scrambledProbe(templates).source); assert.notEqual(other.key, scrambledProbe(templates).key);
  // The scrambled script still works: what it seals opens with its key, with the gesture and its measurements.
  const measure = (await import(`data:text/javascript,${encodeURIComponent(other.source)}`)).default();
  const opened = openReport(await measure.seal({ holdMs: 1600, pointer: 'mouse' }), other.key);
  assert.equal(opened.holdMs, 1600); assert.equal(opened.webdriver, false); assert.deepEqual(opened.env, { touch: 0 });
  // Without this check's cookie, or from another client, there is no script.
  assert.equal((await f.request('/_gate/human/probe.js', { headers: visitor() })).status, 404);
  assert.equal((await f.request('/_gate/human/probe.js', { headers: { ...visitor(), cookie, 'user-agent': 'other' } })).status, 404);
  // A report rewritten in transit, sealed with another check's key, or sent in the old plain form is refused as tampering.
  const genuine = sealReport(HUMAN, '00'.repeat(32));
  for (const [index, report] of [genuine, genuine.replace(/^./, c => (c === 'A' ? 'B' : 'A')), undefined, 'x.y', 42].entries()) {
    const response = await check(f, { headers: visitor(`203.0.113.${60 + index}`), report: report ?? '' });
    assert.equal(response.status, 403); assert.deepEqual(await answer(response), { error: 'human_check_failed', reason: 'automation_detected' });
    assert.ok(f.audit.at(-1).automationSignals.includes('report_tampered'));
  }
  assert.deepEqual(openReport(sealReport({ a: 1 }, 'ab'.repeat(32)), 'ab'.repeat(32)), { a: 1 });
  for (const [text, key] of [[sealReport([1], 'ab'.repeat(32)), 'ab'.repeat(32)], ['', 'ab'.repeat(32)], ['a.b.c', 'ab'.repeat(32)], ['x.y', 'short'], [null, null]]) assert.equal(openReport(text, key), null);
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

test('cloud ranges merge, match both IP versions, and reject malformed lines', () => {
  const ranges = cloudRanges(['# comment', '203.0.113.0/25', '203.0.113.128/25 # adjacent', '198.51.100.7', '2001:db8::/32', '']);
  assert.equal(ranges.size, 3); // The two halves merge into one /24.
  for (const ip of ['203.0.113.0', '203.0.113.255', '198.51.100.7', '::ffff:203.0.113.9', '2001:db8:ffff::1']) assert.equal(ranges.has(ip), true, ip);
  for (const ip of ['203.0.114.0', '198.51.100.8', '2001:db9::1', 'not-an-ip']) assert.equal(ranges.has(ip), false, ip);
  assert.throws(() => cloudRanges(['10.0.0.0/33']), /Invalid cloud range/);
});

test('a datacenter address shortens the pass on the server, and a refusal by the score reads like any failed check', async t => {
  const cloud = cloudRanges(['198.51.100.0/24']);
  const server = { 'x-forwarded-for': '198.51.100.9', 'user-agent': LINUX };
  const logged = await fixture(t, { cloud }, { SANDBOX_CHECK: 'log' });
  assert.equal((await check(logged, { headers: server })).status, 200);
  assert.deepEqual(logged.audit.find(event => event.reason === 'human_pass_issued').automationSignals.slice(-2), ['datacenter', 'sandbox:2']);

  const f = await fixture(t, { cloud }); // enforce is the default
  // A person behind a datacenter VPN: allowed, but the pass lasts an hour. Its cookie looks like any other pass.
  const vpn = await check(f, { headers: server });
  assert.equal(vpn.status, 200); assert.match(vpn.headers.get('set-cookie'), /Max-Age=21600/);
  const home = visitor('203.0.113.10', { 'user-agent': WINDOWS });
  const passed = await check(f, { headers: home });
  f.advance(3601 * 1000);
  assert.equal((await get(f, '/later', { ...server, cookie: f.cookieOf(vpn) })).status, 403);
  assert.equal((await get(f, '/later', { ...home, cookie: f.cookieOf(passed) })).status, 200);

  // Rules that score a browser at the refusal line.
  const scored = { ...basic, sandboxReport: () => ({ score: 4, found: ['server_like'], notes: ['server_like', 'sandbox:4'] }) };
  const strict = await fixture(t, { rules: scored });
  const refused = await check(strict, { headers: server });
  assert.equal(refused.status, 403); assert.deepEqual(await answer(refused), { error: 'human_check_failed', reason: 'sandbox_detected' });

  const off = await fixture(t, { cloud, rules: scored }, { SANDBOX_CHECK: 'off' });
  assert.equal((await check(off, { headers: server })).status, 200);
  assert.ok(!off.audit.find(event => event.reason === 'human_pass_issued').automationSignals.some(note => note.startsWith('sandbox')));
});

test('a rules pack replaces the basic rules, and a missing or incomplete one stops the gateway from starting', async t => {
  const folder = () => {
    const dir = new URL(`../.cache/rules-${randomBytes(6).toString('hex')}/`, import.meta.url);
    mkdirSync(dir, { recursive: true }); t.after(() => rmSync(dir, { recursive: true, force: true }));
    return dir;
  };
  const basicURL = JSON.stringify(new URL('../src/basic.mjs', import.meta.url).href);
  const full = folder(), partial = folder();
  writeFileSync(new URL('index.mjs', full), `export * from ${basicURL};\nexport const name = 'test pack';\n`);
  writeFileSync(new URL('index.mjs', partial), `export { humanReport } from ${basicURL};\n`);
  const pack = await loadRules(fileURLToPath(full));
  assert.equal(pack.name, 'test pack'); assert.equal(pack.humanReport, basic.humanReport);
  await assert.rejects(loadRules(fileURLToPath(partial)), /does not export probe, assets, headerAnomaly, sandboxReport/);
  await assert.rejects(loadRules(fileURLToPath(new URL('missing/', full))), /RULES_DIR has no index\.mjs/);
});

// What Chrome on Windows sends for a page load.
const CHROME = { 'user-agent': WINDOWS, accept: 'text/html,application/xhtml+xml', 'accept-language': 'en-IN,en;q=0.9', 'sec-fetch-mode': 'navigate',
  'sec-fetch-dest': 'document', 'sec-fetch-site': 'none', 'sec-ch-ua': '"Chromium";v="141", "Google Chrome";v="141"' };
const suspicious = (t, overrides = {}, env = {}) => fixture(t, overrides, { HUMAN_CHECK: 'suspicious', ...env });
const lastReason = f => f.audit.at(-1).automationSignals.find(note => note.startsWith('suspect:'));

test('in suspicious mode a person in an ordinary browser never sees the check', async t => {
  const f = await suspicious(t);
  for (const path of ['/', '/article/1', '/article/2']) assert.equal((await get(f, path, visitor('203.0.113.10', CHROME))).text, 'PRIVATE_ORIGIN_CONTENT');
  // Page assets are not page loads.
  const image = { ...CHROME, accept: 'image/avif,image/webp', 'sec-fetch-dest': 'image', 'sec-fetch-mode': 'no-cors', 'accept-language': undefined };
  delete image['accept-language'];
  assert.equal((await get(f, '/logo.png', visitor('203.0.113.10', image))).status, 200);
  // Other ordinary browsers.
  const firefox = { ...CHROME, 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0' }; delete firefox['sec-ch-ua'];
  const webview = { ...firefox, 'user-agent': 'Mozilla/5.0 (Linux; Android 15; Pixel 9; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/141.0.0.0 Mobile Safari/537.36' };
  const safari = { 'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Mobile/15E148 Safari/604.1', accept: 'text/html', 'accept-language': 'en-GB' };
  for (const headers of [firefox, webview, safari]) assert.equal((await get(f, '/article/3', visitor('203.0.113.11', headers))).status, 200, headers['user-agent']);
});

test('in suspicious mode scripts, declared automation, odd headers and datacenter addresses get the check', async t => {
  const f = await suspicious(t, { cloud: cloudRanges(['198.51.100.0/24']) });
  const cases = [
    [{ 'user-agent': 'curl/8.9.1', accept: '*/*' }, 'not_a_browser'],
    [{ 'user-agent': 'python-requests/2.32.3' }, 'not_a_browser'],
    [{ ...CHROME, 'user-agent': WINDOWS.replace('Chrome/', 'HeadlessChrome/') }, 'automation_user_agent'],
  ];
  for (const [headers, reason] of cases) {
    const response = await get(f, '/article/1', visitor('203.0.113.20', headers));
    assert.equal(response.status, 403, reason); assert.equal(lastReason(f), `suspect:${reason}`);
  }
  assert.equal((await get(f, '/article/1', visitor('198.51.100.9', CHROME))).status, 403);
  assert.equal(lastReason(f), 'suspect:datacenter');
  // Python and Go HTTP clients send no Fetch Metadata at all. Node's fetch adds it, so this one is asked directly.
  assert.equal(headerAnomaly({ 'user-agent': WINDOWS, 'accept-language': 'en' }, { document: true }), 'missing_fetch_metadata');
  assert.equal(headerAnomaly(CHROME, { document: true }), null);
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
  assert.deepEqual(await answer(failed), { error: 'human_check_failed', reason: 'automation_detected' });
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

test('Firefox steps to the hop page and back, and the rules hear the result once', async t => {
  const heard = [];
  const listening = { ...basic, humanReport: (report, userAgent, context) => { heard.push(context.returned); return basic.humanReport(report, userAgent, context); } };
  const f = await fixture(t, { rules: listening });
  const firefox = visitor('203.0.113.50', { 'user-agent': FIREFOX });
  const shown = await navigate(f, '/article?id=7', { ...firefox, ...LOAD, 'sec-fetch-site': 'none' });
  assert.equal(shown.status, 403); assert.match(shown.text, /Confirm you are human/);
  // Headers the hop needs.
  assert.equal(shown.headers['cache-control'], 'private, no-cache');
  assert.equal(shown.headers['cross-origin-opener-policy'], 'same-origin');
  assert.equal(shown.headers.vary, '*');
  const id = hopID();
  const stepped = await hopTo(f, id, '/article?id=7', firefox);
  assert.equal(stepped.status, 200);
  assert.match(stepped.text, /\/_gate\/hop\.js/);
  assert.match(stepped.headers['set-cookie'][0], new RegExp(`^hg_hop=${id}; Path=/; HttpOnly; SameSite=Strict; Max-Age=60`));
  assert.equal(stepped.headers['cache-control'], 'no-store, private');
  assert.equal(stepped.headers['cross-origin-opener-policy'], 'same-origin');
  assert.equal((await check(f, { headers: firefox, hop: id })).status, 200, 'came back');
  // Each trip counts once, and only for the browser that made it; no trip is just not back.
  assert.equal((await check(f, { headers: visitor('198.51.100.51', { 'user-agent': FIREFOX }), hop: id })).status, 200);
  const other = hopID();
  assert.equal((await hopTo(f, other, '/', firefox)).status, 200);
  assert.equal((await check(f, { headers: visitor('192.0.2.52', { 'user-agent': `${FIREFOX} Other` }), hop: other })).status, 200);
  assert.equal((await check(f, { headers: visitor('192.0.2.53', CHROME) })).status, 200);
  assert.deepEqual(heard, [true, false, false, false]);
});

test('a check page loaded again straight after its hop is refused, without saying why', async t => {
  const f = await fixture(t);
  const firefox = visitor('203.0.113.60', { 'user-agent': FIREFOX });
  const { cookie } = await hopTo(f, hopID(), '/article?id=7', firefox);
  assert.ok(cookie);
  // Another page, or a request that is not a page load, is just a new check.
  assert.match((await navigate(f, '/other', { ...firefox, ...LOAD, cookie })).text, /Confirm you are human/);
  assert.equal(await errorOf(await f.request('/article?id=7', { headers: { ...firefox, cookie } })), 'human_check_required');
  const reloaded = await navigate(f, '/article?id=7', { ...firefox, ...LOAD, cookie });
  assert.equal(reloaded.status, 403);
  assert.match(reloaded.text, /The check did not pass/); assert.doesNotMatch(reloaded.text, /automat/i);
  assert.match(reloaded.headers['set-cookie'][0], /^hg_hop=; .*Max-Age=0/);
  assert.equal(f.audit.at(-1).reason, 'automation_detected');
  assert.deepEqual(f.audit.at(-1).automationSignals, ['hop_reload']);
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

test('a check page left open swaps its ticket before it runs out, keeps its script, and starts over after ten minutes', async t => {
  const heard = [];
  const listening = { ...basic, humanReport: (report, userAgent, context) => { heard.push(context.returned); return basic.humanReport(report, userAgent, context); } };
  const f = await fixture(t, { rules: listening });
  const firefox = visitor('203.0.113.60', { 'user-agent': FIREFOX });
  const renew = cookie => f.post('/_gate/human/renew', {}, cookie, firefox);
  // Left alone, a ticket is gone after two minutes.
  const idle = await f.post('/_gate/human/options', {}, null, firefox);
  const idleKey = probeKey(f, f.cookieOf(idle));
  f.advance(121000);
  const late = await f.post('/_gate/human/verify', { nonce: '0', report: sealReport(HUMAN, idleKey) }, f.cookieOf(idle), firefox);
  assert.equal(await errorOf(late), 'invalid_challenge');
  assert.equal(await errorOf(await renew(f.cookieOf(idle))), 'invalid_challenge'); // Too late to swap, too.

  const id = hopID();
  assert.equal((await hopTo(f, id, '/', firefox)).status, 200);
  const issued = await f.post('/_gate/human/options', { hop: id }, null, firefox);
  const first = f.cookieOf(issued), key = probeKey(f, first);
  let cookie = first, options = await issued.json();
  for (let i = 0; i < 3; i++) {
    f.advance(90000);
    const swapped = await renew(cookie);
    assert.equal(swapped.status, 200);
    const next = await swapped.json();
    assert.notEqual(next.challenge, options.challenge); assert.equal(next.holdMs, 1500);
    cookie = f.cookieOf(swapped); options = next;
    // The page keeps the script it loaded: same key, so what it measured so far still counts.
    assert.equal(probeKey(f, cookie), key);
  }
  assert.equal(f.audit.filter(event => event.reason === 'human_check_renewed').length, 3);
  // The old ticket stopped working when it was swapped.
  assert.equal(await errorOf(await f.post('/_gate/human/verify', { nonce: '0', report: sealReport(HUMAN, key) }, first, firefox)), 'invalid_challenge');
  // 4.5 minutes after the page loaded, the hold is answered with the newest ticket and the original script's seal.
  f.advance(20000);
  const passed = await f.post('/_gate/human/verify', { nonce: solve(options.challenge, options.difficulty), report: sealReport(HUMAN, key) }, cookie, firefox);
  assert.equal(passed.status, 200, await passed.clone().text());
  // The hop's result is kept through the swaps.
  assert.deepEqual(heard, [true]);

  // Only another check page of this browser may swap a ticket, and only for ten minutes after the check began.
  const other = await f.post('/_gate/human/options', {}, null, firefox);
  assert.equal(await errorOf(await f.post('/_gate/human/renew', {}, f.cookieOf(other), visitor('203.0.113.60', CHROME))), 'invalid_challenge');
  const open = await f.post('/_gate/human/options', {}, null, firefox);
  cookie = f.cookieOf(open);
  for (let i = 0; i < 6; i++) { f.advance(95000); const swapped = await renew(cookie); assert.equal(swapped.status, 200); cookie = f.cookieOf(swapped); }
  f.advance(90000);
  assert.equal(await errorOf(await renew(cookie)), 'invalid_challenge');
  // The page then starts a new check.
  assert.equal((await f.post('/_gate/human/options', {}, null, firefox)).status, 200);
});
