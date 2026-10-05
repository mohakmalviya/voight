import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { createFixture } from './fixture.mjs';
import { leadingZeroBits, privateCacheControl } from '../src/gateway.mjs';

const ASSETS = { '/_gate/index.html': { body: '<h1>Admission required</h1>', type: 'text/html' } };
async function fixture(t, overrides = {}, env = {}, handler) {
  const f = await createFixture({ challengeDifficulty: 4, ...overrides }, handler, ASSETS, { MODE: 'public', TRUSTED_PROXIES: '127.0.0.1', HUMAN_CHECK: 'off', ...env });
  t.after(f.close); return f;
}
const from = ip => ({ 'x-forwarded-for': ip });
// fetch() always sends sec-fetch-mode: cors, so navigation headers need a raw request.
function raw(f, path, headers) {
  return new Promise((resolve, reject) => {
    http.get(f.config.origin + path, { headers: { 'user-agent': 'test-browser', ...headers } }, response => { response.resume(); resolve(response.statusCode); }).on('error', reject);
  });
}
async function status(f, path, headers = {}) {
  const response = await f.request(path, { headers }); await response.arrayBuffer(); return response.status;
}
function solve(challenge, difficulty) {
  for (let nonce = 0; ; nonce++) {
    if (leadingZeroBits(createHash('sha256').update(`${challenge}:${nonce}`).digest()) >= difficulty) return String(nonce);
  }
}
async function clearance(f, headers = {}) {
  const issued = await f.post('/_gate/challenge/options', {}, null, headers);
  assert.equal(issued.status, 200); const { challenge, difficulty } = await issued.json();
  const verified = await f.post('/_gate/challenge/verify', { nonce: solve(challenge, difficulty) }, f.cookieOf(issued), headers);
  assert.equal(verified.status, 200, await verified.clone().text()); await verified.text();
  return { cookie: f.cookieOf(verified), difficulty };
}

test('anonymous visitors read the site without any login, and the site keeps its own page policy', async t => {
  const f = await fixture(t, {}, {}, (_, res) => {
    res.setHeader('content-security-policy', "default-src 'self' https://cdn.example");
    res.setHeader('cache-control', 'public, max-age=600, s-maxage=3600');
    res.setHeader('set-cookie', 'origin=leak');
    res.end('PUBLIC_PAGE');
  });
  const response = await f.request('/article', { headers: { 'accept-language': 'hi-IN' } });
  assert.equal(response.status, 200); assert.equal(await response.text(), 'PUBLIC_PAGE');
  assert.equal(response.headers.get('content-security-policy'), "default-src 'self' https://cdn.example");
  assert.equal(response.headers.get('cache-control'), 'private, max-age=600');
  assert.equal(response.headers.get('x-robots-tag'), null);
  assert.equal(response.headers.get('set-cookie'), null);
  assert.equal(f.lastHeaders()['x-human-gate-user'], undefined);
  assert.equal(f.lastHeaders()['accept-language'], 'hi-IN');
});

test('budgets follow the network, so dropping cookies or changing user agent does not reset them', async t => {
  const f = await fixture(t, { resourcesPerWindow: 2 });
  assert.equal(await status(f, '/a', from('203.0.113.7')), 200);
  assert.equal(await status(f, '/b', { ...from('203.0.113.7'), 'user-agent': 'other-browser' }), 200);
  assert.equal(await status(f, '/c', { ...from('203.0.113.7'), cookie: 'hg_clearance=forged' }), 429);
  assert.equal(await status(f, '/c', from('198.51.100.9')), 200); // A different network has its own budget.
  assert.equal(f.hits(), 3);
});

test('IPv6 visitors share one budget per /64 and forwarded headers from untrusted peers are ignored', async t => {
  const f = await fixture(t, { resourcesPerWindow: 1 });
  assert.equal(await status(f, '/a', from('2001:db8:5:6::1')), 200);
  assert.equal(await status(f, '/b', from('2001:db8:5:6:ffff::2')), 429);
  assert.equal(await status(f, '/b', from('2001:db8:5:7::1')), 200);

  const g = await fixture(t, { resourcesPerWindow: 1 }, { TRUSTED_PROXIES: '' });
  assert.equal(await status(g, '/a', from('203.0.113.1')), 200);
  assert.equal(await status(g, '/b', from('203.0.113.2')), 429); // Spoofed header: same socket peer, same budget.
});

test('ignoring limits escalates to a timed block that lifts by itself and grows on repeat', async t => {
  const f = await fixture(t, { resourcesPerWindow: 1, extractionWindowSeconds: 60, strikesPerWindow: 2, banSeconds: 60, maxBanSeconds: 3600 });
  const visitor = from('203.0.113.50');
  assert.equal(await status(f, '/a', visitor), 200);
  assert.equal(await status(f, '/b', visitor), 429);
  assert.equal(await status(f, '/c', visitor), 429);
  const blocked = await f.request('/d', { headers: { ...visitor, accept: 'text/html' } });
  assert.equal(blocked.status, 429); assert.equal(blocked.headers.get('retry-after'), '60');
  assert.match(await blocked.text(), /Temporarily blocked[\s\S]*resumes automatically in about 60 seconds/);
  assert.equal(await status(f, '/a', visitor), 429); // Even a page it may already read is blocked.
  assert.equal(await status(f, '/_gate/index.html', visitor), 200); // The notice's own assets still load.
  assert.equal(await status(f, '/a', from('198.51.100.1')), 200); // Other networks are unaffected.
  assert.equal(f.audit.filter(e => e.reason === 'temporarily_blocked').length, 2);

  f.advance(61000);
  assert.equal(await status(f, '/e', visitor), 200);
  assert.equal(await status(f, '/f', visitor), 429);
  assert.equal(await status(f, '/g', visitor), 429);
  const repeat = await f.request('/h', { headers: visitor });
  assert.equal(repeat.status, 429); assert.equal(repeat.headers.get('retry-after'), '240'); await repeat.text();
  assert.equal(f.store.bans()[0].count, 2);
});

test('over budget, a browser gets a no-puzzle check; solving it gives the visitor its own budget', async t => {
  const f = await fixture(t, { resourcesPerWindow: 1 });
  const visitor = from('203.0.113.80');
  assert.equal(await status(f, '/a', visitor), 200);
  const page = await f.request('/b', { headers: { ...visitor, accept: 'text/html' } });
  assert.equal(page.status, 429); assert.match(await page.text(), /\/_gate\/challenge\.js/);
  const api = await f.request('/b', { headers: visitor });
  assert.equal((await api.json()).error, 'resource_budget'); // Programmatic callers get JSON, not a page.

  const { cookie } = await clearance(f, visitor);
  assert.match(cookie, /^hg_clearance=/);
  assert.equal(await status(f, '/b', { ...visitor, cookie }), 200);
  assert.equal(await status(f, '/c', { ...visitor, cookie }), 429); // The clearance budget is finite too.
  assert.equal(await status(f, '/c', visitor), 429); // The network budget is still spent.
});

test('each clearance costs more work, the supply is capped, and solutions cannot be forged or replayed', async t => {
  const f = await fixture(t, { clearancesPerWindow: 2, resourcesPerWindow: 1 });
  const visitor = from('203.0.113.90');
  assert.equal((await clearance(f, visitor)).difficulty, 4);
  assert.equal((await clearance(f, visitor)).difficulty, 5);
  const capped = await f.post('/_gate/challenge/options', {}, null, visitor);
  assert.equal(capped.status, 429); assert.equal((await capped.json()).error, 'challenge_limit');
  assert.equal(await status(f, '/a', visitor), 200);
  const page = await f.request('/b', { headers: { ...visitor, accept: 'text/html' } });
  assert.doesNotMatch(await page.text(), /challenge\.js/); // No more checks offered once the cap is reached.

  const other = from('198.51.100.90');
  const issued = await f.post('/_gate/challenge/options', {}, null, other); const { challenge, difficulty } = await issued.json();
  let wrong = 0; while (leadingZeroBits(createHash('sha256').update(`${challenge}:${wrong}`).digest()) >= difficulty) wrong++;
  assert.equal((await f.post('/_gate/challenge/verify', { nonce: String(wrong) }, f.cookieOf(issued), other)).status, 403);
  assert.equal((await f.post('/_gate/challenge/verify', { nonce: solve(challenge, difficulty) }, f.cookieOf(issued), other)).status, 403);

  const again = await f.post('/_gate/challenge/options', {}, null, other); const fresh = await again.json();
  const moved = await f.post('/_gate/challenge/verify', { nonce: solve(fresh.challenge, fresh.difficulty) }, f.cookieOf(again), from('192.0.2.1'));
  assert.equal(moved.status, 403); // A challenge solved for one network cannot clear another.
});

test('public mode accepts links from other sites but not cross-site embedding, and has no passkey endpoints', async t => {
  const f = await fixture(t);
  assert.equal(await raw(f, '/', { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate' }), 200);
  assert.equal(await raw(f, '/logo.png', { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'no-cors' }), 403);
  assert.equal((await f.post('/_gate/login/options', {})).status, 404);
  assert.equal((await f.post('/_gate/register/options', { invite: 'x'.repeat(43) })).status, 404);
  assert.equal((await f.request('/', { method: 'POST' })).status, 405);
});

test('private mode keeps passkey admission and offers no proof-of-work bypass', async t => {
  const f = await createFixture({}, undefined, ASSETS, { MODE: 'private' }); t.after(f.close);
  assert.equal(await status(f, '/'), 401);
  assert.equal((await f.post('/_gate/challenge/options', {})).status, 404);
  assert.equal(f.hits(), 0);
});

test('helpers: cache directives become private and zero bits are counted exactly', () => {
  assert.equal(privateCacheControl(null), 'no-store, private');
  assert.equal(privateCacheControl('no-store'), 'no-store, private');
  assert.equal(privateCacheControl('public, max-age=60, s-maxage=600, proxy-revalidate'), 'private, max-age=60');
  assert.equal(leadingZeroBits(Buffer.from([0, 0, 0x10])), 19);
  assert.equal(leadingZeroBits(Buffer.from([0x80])), 0);
  assert.equal(leadingZeroBits(Buffer.from([0, 0])), 16);
});
