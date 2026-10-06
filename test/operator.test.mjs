import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { createFixture } from './fixture.mjs';
import { configFromEnv } from '../src/config.mjs';
import { declaredAIAgent } from '../src/agents.mjs';
import { parsePolicy, matchPolicy, loadPolicy } from '../src/policy.mjs';
import { previewTags } from '../src/preview.mjs';
import { createMetrics, metricsServer } from '../src/metrics.mjs';

const ASSETS = { '/_gate/index.html': { body: '<h1>Admission required</h1>', type: 'text/html' } };
const POST = '<html><head><title>Ignored &amp; title</title><meta property="og:title" content="Post &amp; title">'
  + '<meta name=\'description\' content=\'A short "summary"\'><meta property="og:image" content="/og.png"><meta name="viewport" content="width=device-width"></head>'
  + '<body>SECRET BODY</body></html>';
const site = (req, res) => {
  if (req.url === '/post') { res.setHeader('content-type', 'text/html; charset=utf-8'); return res.end(POST); }
  res.end(req.url === '/og.png' ? 'PNG' : 'PRIVATE_ORIGIN_CONTENT');
};
async function fixture(t, overrides = {}, env = {}) {
  const f = await createFixture({ challengeDifficulty: 4, ...overrides }, site, ASSETS, { MODE: 'public', TRUSTED_PROXIES: '127.0.0.1', HUMAN_CHECK: 'always', ...env });
  t.after(f.close); return f;
}
const visitor = (ip = '203.0.113.10', extra = {}) => ({ 'x-forwarded-for': ip, ...extra });
const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36';
async function get(f, path, headers) {
  const response = await f.request(path, { headers });
  return { status: response.status, text: await response.text() };
}
// fetch() always sends sec-fetch-mode, which link-preview clients never do, so those need a raw request.
function raw(f, path, headers) {
  return new Promise((resolve, reject) => {
    http.get(f.config.origin + path, { headers }, response => {
      let text = ''; response.setEncoding('utf8');
      response.on('data', chunk => { text += chunk; }).on('end', () => resolve({ status: response.statusCode, text }));
    }).on('error', reject);
  });
}
const lastSignals = f => f.audit.at(-1).automationSignals;

test('every gate page hides a link that only tools follow, and fetching it blocks the network', async t => {
  const f = await fixture(t);
  const page = await get(f, '/article', visitor('203.0.113.10', { accept: 'text/html' }));
  assert.equal(page.status, 403);
  const trap = /<template><a href="(\/_gate\/more\/[\w-]{43})">/.exec(page.text)?.[1];
  assert.ok(trap, 'the check page carries the hidden link');
  const again = await get(f, '/article', visitor('203.0.113.10', { accept: 'text/html' }));
  assert.notEqual(/\/_gate\/more\/[\w-]{43}/.exec(again.text)[0], trap); // A fresh one on every page.
  const hit = await f.request(trap, { headers: visitor('203.0.113.10') });
  assert.equal(hit.status, 429); assert.equal((await hit.json()).error, 'honeypot');
  assert.equal(hit.headers.get('retry-after'), '300');
  assert.deepEqual(lastSignals(f), ['honeypot']);
  const blocked = await f.request('/article', { headers: visitor('203.0.113.10') });
  assert.equal(blocked.status, 429); assert.equal((await blocked.json()).error, 'temporarily_blocked');
  // The page a person would see if they opened it from the page source says what happened.
  const explained = await get(f, '/_gate/more/x', visitor('203.0.113.11', { accept: 'text/html' }));
  assert.match(explained.text, /Automated browsing detected[\s\S]*only automated tools find it[\s\S]*Access resumes automatically/);
  assert.doesNotMatch(explained.text, /Try again/);
  assert.equal((await get(f, '/article', visitor('198.51.100.20'))).status, 403); // Other networks only get the check.
  assert.equal(f.hits(), 0);
});

test('the hidden link can only log, or be left out', async t => {
  const logged = await fixture(t, {}, { HONEYPOT: 'log' });
  assert.equal((await get(logged, '/_gate/more/abc', visitor())).status, 404);
  assert.deepEqual(lastSignals(logged), ['honeypot']);
  assert.equal((await logged.request('/article', { headers: visitor() }).then(r => r.json())).error, 'human_check_required');
  const off = await fixture(t, {}, { HONEYPOT: 'off' });
  assert.doesNotMatch((await get(off, '/article', visitor('203.0.113.10', { accept: 'text/html' }))).text, /<template>/);
  assert.equal((await get(off, '/_gate/more/abc', visitor())).status, 404);
  assert.deepEqual(lastSignals(off), []);
  assert.throws(() => configFromEnv({ HONEYPOT: 'maybe' }), /HONEYPOT/);
});

test('operator rules allow, deny or always check by path, user agent, header or network, before anything else', async t => {
  const policy = parsePolicy({ rules: [
    { name: 'office', action: 'allow', cidr: ['192.0.2.0/24', '2001:db8::/32'] },
    { name: 'bad-scraper', action: 'deny', userAgent: 'ScrapeKit' },
    { name: 'no-referer', action: 'deny', headers: { Referer: '^$' }, path: '^/private/' },
    { name: 'admin', action: 'check', path: '^/admin/' },
  ] });
  const f = await fixture(t, { policy }, { HUMAN_CHECK: 'suspicious' });
  const browser = { 'user-agent': CHROME, 'sec-ch-ua': '"Chromium";v="154", "Google Chrome";v="154"', 'accept-language': 'en' };
  // An allowed network skips the check, even with HUMAN_CHECK=always behaviour and a self-declared AI agent.
  assert.equal((await get(f, '/article', visitor('192.0.2.44', { 'user-agent': 'curl/8.9' }))).text, 'PRIVATE_ORIGIN_CONTENT');
  assert.equal((await get(f, '/article', visitor('192.0.2.44', { 'user-agent': 'GPTBot/1.2' }))).status, 200);
  assert.deepEqual(lastSignals(f), ['policy:office']);
  const denied = await f.request('/article', { headers: visitor('203.0.113.50', { 'user-agent': 'Mozilla/5.0 ScrapeKit/2' }) });
  assert.equal(denied.status, 403); assert.equal((await denied.json()).error, 'policy_denied');
  assert.match((await get(f, '/x', visitor('203.0.113.50', { 'user-agent': 'ScrapeKit', accept: 'text/html' }))).text, /Access refused/);
  assert.equal((await f.request('/private/a', { headers: visitor('203.0.113.51', { 'user-agent': CHROME }) }).then(r => r.json())).error, 'policy_denied');
  // An ordinary browser reads normally, except where a rule asks for the check.
  assert.equal((await get(f, '/article', visitor('203.0.113.52', browser))).status, 200);
  const admin = await f.request('/admin/panel', { headers: visitor('203.0.113.52', browser) });
  assert.equal(admin.status, 403); assert.equal((await admin.json()).error, 'human_check_required');
  assert.deepEqual(lastSignals(f), ['policy:admin', 'suspect:policy']);
});

test('operator rules are validated when they load', async () => {
  assert.throws(() => parsePolicy({}), /list of rules/);
  assert.throws(() => parsePolicy([{ name: 'x y', action: 'allow', path: '/' }]), /needs a name/);
  assert.throws(() => parsePolicy([{ name: 'a', action: 'ban', path: '/' }]), /allow, deny or check/);
  assert.throws(() => parsePolicy([{ name: 'a', action: 'allow' }]), /at least one/);
  assert.throws(() => parsePolicy([{ name: 'a', action: 'allow', path: '(' }]), /not a regular expression/);
  assert.throws(() => parsePolicy([{ name: 'a', action: 'allow', cidr: ['10.0.0.0/33'] }]), /invalid cidr/);
  assert.throws(() => parsePolicy([{ name: 'a', action: 'allow', headers: { 'bad header': 'x' } }]), /invalid header name/);
  assert.throws(() => parsePolicy([{ name: 'a', action: 'allow', path: '/', ip: '1.2.3.4' }]), /unknown field ip/);
  await assert.rejects(loadPolicy('./no-such-policy.json'), /Cannot read POLICY_FILE/);
  assert.deepEqual((await loadPolicy(new URL('../docs/policy.example.json', import.meta.url))).map(rule => rule.action), ['allow', 'allow', 'allow', 'deny', 'check', 'check']);
  const rules = parsePolicy([{ name: 'first', action: 'check', path: '^/a' }, { name: 'second', action: 'deny', path: '^/a' }]);
  assert.equal(matchPolicy(rules, { path: '/a', userAgent: '', headers: {}, ip: '203.0.113.1' }).name, 'first');
  assert.equal(matchPolicy(rules, { path: '/b', userAgent: '', headers: {}, ip: '203.0.113.1' }), null);
  assert.equal(matchPolicy(parsePolicy([{ name: 'net', action: 'allow', cidr: ['203.0.113.0/24'] }]), { path: '/', userAgent: '', headers: {}, ip: 'unknown' }), null);
});

test('machine-read files stay open by default: robots.txt, the favicon and everything under /.well-known/', async t => {
  const f = await fixture(t);
  for (const path of ['/robots.txt', '/favicon.ico', '/.well-known/security.txt', '/.well-known/apple-app-site-association']) {
    assert.equal((await get(f, path, visitor())).status, 200, path);
  }
  assert.equal((await get(f, '/.well-known/security.txt', visitor('203.0.113.10', { 'user-agent': 'ClaudeBot/1.0' }))).status, 200);
  for (const path of ['/.well-known', '/favicon.ico.bak', '/well-known/x']) assert.equal((await get(f, path, visitor())).status, 403, path);
  assert.deepEqual(configFromEnv({ OPEN_PATHS: '/feed.xml,/feeds/*' }).openPaths, ['/feed.xml', '/feeds/*']);
  assert.throws(() => configFromEnv({ OPEN_PATHS: '/a*b' }), /OPEN_PATHS/);
});

test('Firefox AI features that fetch a page for a summary are refused as AI agents', async t => {
  assert.equal(declaredAIAgent({ 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; rv:143.0) Gecko/20100101 Firefox/143.0', 'x-firefox-ai': '1' }), 'firefox_ai');
  const f = await fixture(t, {}, { HUMAN_CHECK: 'off' });
  const refused = await f.request('/article', { headers: visitor('203.0.113.10', { 'x-firefox-ai': '1' }) });
  assert.equal(refused.status, 403); assert.equal((await refused.json()).error, 'ai_agent');
  assert.deepEqual(lastSignals(f), ['ai_agent:firefox_ai']);
});

test('link previews: chat apps get the page\'s own preview tags and image, never the page itself', async t => {
  const f = await fixture(t, {}, { OPEN_GRAPH: 'on' });
  const slack = { 'user-agent': 'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)', 'x-forwarded-for': '203.0.113.60' };
  const card = await raw(f, '/post', slack);
  assert.equal(card.status, 200);
  assert.ok(card.text.includes(`<meta property="og:title" content="Post &amp; title"><meta name="description" content="A short &quot;summary&quot;"><meta property="og:image" content="${f.config.origin}/og.png">`));
  assert.match(card.text, /Confirm you are human/);
  assert.doesNotMatch(card.text, /SECRET BODY|viewport" content="width=device-width"><meta/);
  assert.equal((await raw(f, '/og.png', slack)).text, 'PNG'); // The card's image is readable.
  const other = await raw(f, '/other.png', slack); // Anything else gets the check page, and files are not read for tags.
  assert.match(other.text, /Confirm you are human/); assert.doesNotMatch(other.text, /og:title|PRIVATE_ORIGIN_CONTENT/);
  assert.equal(f.hits(), 2); // One read for the tags, one for the image.
  const api = await raw(f, '/data.json', { ...slack, accept: 'application/json' });
  assert.equal(api.status, 403); assert.equal(JSON.parse(api.text).error, 'human_check_required');
  await raw(f, '/post', slack); assert.equal(f.hits(), 2); // Cached.
  // A browser gets the ordinary check page, without the tags.
  const browser = await get(f, '/post', visitor('203.0.113.61', { accept: 'text/html' }));
  assert.equal(browser.status, 403); assert.doesNotMatch(browser.text, /og:title/);
  const off = await fixture(t);
  const plain = await raw(off, '/post', { ...slack, accept: 'text/html' });
  assert.equal(plain.status, 403); assert.doesNotMatch(plain.text, /og:title/);
  assert.throws(() => configFromEnv({ OPEN_GRAPH: 'yes' }), /OPEN_GRAPH/);
});

test('preview tags are read from the head only, decoded once, with the title standing in for a missing og:title', () => {
  assert.deepEqual(previewTags('<head><title>My &#39;page&#x27;</title><meta name="twitter:card" content="summary"><meta property="og:url" content=""></head><meta property="og:title" content="late">'),
    [['property', 'og:title', "My 'page'"], ['name', 'twitter:card', 'summary']]);
  assert.deepEqual(previewTags('<meta content="x" property="OG:Description"><meta http-equiv="refresh" content="0">'), [['property', 'og:description', 'x']]);
});

test('the operator\'s contact appears on gate pages, with the reference filled in', async t => {
  const f = await fixture(t, {}, { CONTACT: 'admin@example.com' });
  const page = await get(f, '/article', visitor('203.0.113.10', { accept: 'text/html' }));
  const reference = /Reference <code>([\w-]+)<\/code>/.exec(page.text)[1];
  assert.match(page.text, new RegExp(`<a href="mailto:admin@example.com\\?subject=Voight%20reference%20${reference}">Contact the operator</a>`));
  const refused = await get(f, '/a', visitor('203.0.113.10', { accept: 'text/html', 'user-agent': 'GPTBot/1.2' }));
  assert.match(refused.text, /If this keeps happening, <a href="mailto:admin@example.com\?subject=[^"]+">contact this website’s operator<\/a>/);
  assert.equal(configFromEnv({ CONTACT: 'https://example.com/contact' }).contact, 'https://example.com/contact');
  assert.throws(() => configFromEnv({ CONTACT: 'javascript:alert(1)' }), /CONTACT/);
  assert.throws(() => configFromEnv({ CONTACT: 'a@b.c"><script>' }), /CONTACT/);
});

test('metrics count decisions and signal names, never values or visitors', async t => {
  const metrics = createMetrics();
  metrics.record({ status: 403, reason: 'automation_detected', chargedBytes: 0, automationSignals: ['webdriver', 'moves:40', 'devtools:5.4', 'Odd Note', 'moves:12'] });
  metrics.record({ status: 200, reason: 'admitted', chargedBytes: 1200, automationSignals: [] });
  const text = metrics.render();
  assert.match(text, /voight_requests_total\{status="403",reason="automation_detected"\} 1/);
  assert.match(text, /voight_requests_total\{status="200",reason="admitted"\} 1/);
  assert.match(text, /voight_signals_total\{signal="moves"\} 1/);
  assert.match(text, /voight_charged_bytes_total 1200/);
  assert.doesNotMatch(text, /Odd|5\.4/);
  const server = metricsServer(metrics).listen(0, '127.0.0.1'); await once(server, 'listening'); t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;
  assert.equal(await fetch(`${base}/metrics`).then(r => r.text()), text);
  assert.equal((await fetch(`${base}/other`)).status, 404);
  assert.equal(configFromEnv({ METRICS_PORT: '9464' }).metricsPort, 9464);
  assert.equal(configFromEnv({}).metricsPort, null);
});
