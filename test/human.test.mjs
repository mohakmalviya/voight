import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createFixture } from './fixture.mjs';
import { leadingZeroBits } from '../src/gateway.mjs';
import { humanReport } from '../src/automation.mjs';
import { declaredAIAgent } from '../src/agents.mjs';
import { Store } from '../src/store.mjs';
import { cloudRanges, sandboxReport } from '../src/sandbox.mjs';

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
  const f = await createFixture({ challengeDifficulty: 4, resolver, ...overrides }, undefined, ASSETS, { MODE: 'public', TRUSTED_PROXIES: '127.0.0.1', ...env });
  t.after(f.close); return f;
}
const visitor = (ip = '203.0.113.10', extra = {}) => ({ 'x-forwarded-for': ip, ...extra });
const page = { accept: 'text/html' };
function solve(challenge, difficulty) {
  for (let nonce = 0; ; nonce++) {
    if (leadingZeroBits(createHash('sha256').update(`${challenge}:${nonce}`).digest()) >= difficulty) return String(nonce);
  }
}
// Runs the check the way the page does: ask, hold for a moment, then report.
async function check(f, { signals = {}, wait = 1600, headers = visitor(), verifyHeaders = headers, nonce } = {}) {
  const issued = await f.post('/_gate/human/options', {}, null, headers);
  assert.equal(issued.status, 200);
  const { challenge, difficulty, holdMs } = await issued.json();
  assert.equal(holdMs, 1500);
  f.advance(wait);
  return f.post('/_gate/human/verify', { nonce: nonce ?? solve(challenge, difficulty), signals: { ...HUMAN, ...signals } }, f.cookieOf(issued), verifyHeaders);
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
  const api = await f.request('/data.json', { headers: visitor() });
  assert.equal(api.status, 403); assert.equal(await errorOf(api), 'human_check_required');
  assert.equal((await get(f, '/robots.txt', visitor())).status, 200); // Crawlers can always read the rules.
  assert.equal(f.hits(), 1);
});

test('holding the button with a real gesture earns a day-long pass bound to this browser', async t => {
  const f = await fixture(t);
  const passed = await check(f);
  assert.equal(passed.status, 200, await passed.clone().text());
  assert.match(passed.headers.get('set-cookie'), /^hg_human=[\w-]{43}; Path=\/; HttpOnly; SameSite=Lax; Max-Age=86400/);
  const cookie = f.cookieOf(passed);
  assert.equal((await get(f, '/article', visitor('203.0.113.10', { ...page, cookie }))).text, 'PRIVATE_ORIGIN_CONTENT');
  // A new network address (mobile carriers rotate them) keeps the pass; another client copying the cookie does not.
  assert.equal((await get(f, '/next', visitor('198.51.100.20', { cookie }))).status, 200);
  assert.equal((await get(f, '/next', visitor('203.0.113.10', { cookie, 'user-agent': 'scraper/1.0' }))).status, 403);
  const issued = f.audit.find(event => event.reason === 'human_pass_issued');
  assert.deepEqual(issued.automationSignals, ['pointer:mouse', 'moves:9', 'sandbox:0']);
  f.advance(86401 * 1000);
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
  assert.deepEqual(report, { automated: false, trusted: false, holdMs: 0, jumped: false, notes: ['pointer:unknown', 'moves:0'] });
  // Touch and keyboard users never hover, and a frameless phone browser is not headless.
  assert.equal(humanReport({ ...HUMAN, pointer: 'touch', path: [] }).jumped, false);
  assert.equal(humanReport({ ...HUMAN, frame: [0, 0], plugins: 0 }, 'Mozilla/5.0 (Linux; Android 15) Chrome/141.0 Mobile Safari/537.36').automated, false);
  // A slow, careful hand creeping one pixel at a time is not mistaken for a script.
  assert.equal(humanReport({ ...HUMAN, path: Array.from({ length: 30 }, () => [1, 0, 17]) }).automated, false);
  assert.deepEqual((await f.post('/_gate/human/verify', { signals: HUMAN }, null, visitor())).status, 403); // No issued check.
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
  // Malformed or missing reports count for nothing; the other checks still apply.
  for (const env of [undefined, null, [], 'x', { gpu: 7, fonts: 'Segoe UI', voices: -1, screen: [1, 2], tz: 5 }]) assert.equal(sandboxReport(env, WINDOWS).score, 0);
});

test('sandbox scores are only recorded in log mode, and refuse or shorten passes in enforce mode', async t => {
  const cloud = cloudRanges(['198.51.100.0/24']);
  const server = { 'x-forwarded-for': '198.51.100.9', 'user-agent': LINUX };
  const logged = await fixture(t, { cloud });
  const allowed = await check(logged, { signals: { env: SERVER }, headers: server });
  assert.equal(allowed.status, 200);
  assert.deepEqual(logged.audit.find(event => event.reason === 'human_pass_issued').automationSignals.slice(-6),
    ['datacenter', 'software_gpu', 'no_media_devices', 'bare_screen', 'utc_clock', 'sandbox:7']);

  const f = await fixture(t, { cloud }, { SANDBOX_CHECK: 'enforce' });
  const refused = await check(f, { signals: { env: SERVER }, headers: server });
  assert.equal(refused.status, 403); assert.equal(await errorOf(refused), 'sandbox_detected');
  // A real laptop behind a datacenter VPN: allowed, but the pass lasts an hour.
  const vpn = await check(f, { signals: { env: LAPTOP }, headers: { 'x-forwarded-for': '198.51.100.10', 'user-agent': WINDOWS } });
  assert.equal(vpn.status, 200); assert.match(vpn.headers.get('set-cookie'), /Max-Age=3600/);
  const home = await check(f, { signals: { env: LAPTOP }, headers: { 'x-forwarded-for': '203.0.113.10', 'user-agent': WINDOWS } });
  assert.equal(home.status, 200); assert.match(home.headers.get('set-cookie'), /Max-Age=86400/);

  const off = await fixture(t, { cloud }, { SANDBOX_CHECK: 'off' });
  assert.equal((await check(off, { signals: { env: SERVER }, headers: server })).status, 200);
  assert.ok(!off.audit.find(event => event.reason === 'human_pass_issued').automationSignals.some(note => note.startsWith('sandbox')));
});
