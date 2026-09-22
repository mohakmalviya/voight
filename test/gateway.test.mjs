import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { Store, token } from '../src/store.mjs';
import { createGateway } from '../src/gateway.mjs';
import { configFromEnv } from '../src/config.mjs';
import { authenticator } from './authenticator.mjs';

async function fixture(t, overrides = {}) {
  let hits = 0, lastHeaders, time = Date.now();
  const upstream = http.createServer((req, res) => {
    hits++; lastHeaders = req.headers;
    if (req.url === '/redirect') { res.writeHead(302, { location: 'https://example.com/' }); return res.end(); }
    res.setHeader('set-cookie', 'hg_session=attacker'); res.setHeader('cache-control', 'public');
    res.end('PRIVATE_ORIGIN_CONTENT');
  }).listen(0, '127.0.0.1'); await once(upstream, 'listening');
  const store = new Store(':memory:', () => time);
  const config = { ...configFromEnv({}), upstream: `http://127.0.0.1:${upstream.address().port}`, ...overrides };
  const audit = [];
  const gateway = createGateway({ config, store, assets: { '/_gate/index.html': { body: '<h1>Admission required</h1>', type: 'text/html' } }, audit: event => audit.push(event) }).listen(0, '127.0.0.1');
  await once(gateway, 'listening'); config.origin = `http://localhost:${gateway.address().port}`;
  t.after(async () => { gateway.closeAllConnections(); upstream.closeAllConnections(); await Promise.all([new Promise(r => gateway.close(r)), new Promise(r => upstream.close(r))]); store.close(); });
  const headers = { 'user-agent': 'test-browser', host: new URL(config.origin).host };
  const request = (path = '/', init = {}) => fetch(`${config.origin}${path}`, { ...init, headers: { ...headers, ...init.headers }, redirect: 'manual' });
  const post = (path, body, cookie, extra = {}) => request(path, { method: 'POST', headers: { origin: config.origin, 'content-type': 'application/json', ...(cookie ? { cookie } : {}), ...extra }, body: JSON.stringify(body) });
  const auth = authenticator(config.rpID, config.origin);
  const cookieOf = response => response.headers.get('set-cookie')?.split(';')[0];
  async function enroll() {
    const invite = store.invite('test-reader');
    const options = await post('/_gate/register/options', { invite }); assert.equal(options.status, 200);
    const challenge = await options.json();
    const response = await post('/_gate/register/verify', auth.register(challenge.challenge), cookieOf(options));
    assert.equal(response.status, 200, await response.clone().text());
    return cookieOf(response);
  }
  return { store, config, auth, request, post, enroll, cookieOf, audit, hits: () => hits, lastHeaders: () => lastHeaders, advance: ms => { time += ms; } };
}

test('unauthenticated paths and forged cookies never reach upstream', async t => {
  const f = await fixture(t);
  for (const path of ['/', '/api/private', '/data.json', '/assets/report.pdf', '/%2e%2e/private', '/robots.txt']) {
    const response = await f.request(path, { headers: { cookie: `hg_session=${token()}`, 'x-forwarded-for': '1.2.3.4' } });
    assert.equal(response.status, 401); assert.doesNotMatch(await response.text(), /PRIVATE_ORIGIN/);
  }
  assert.equal(f.hits(), 0);
});
test('real signed WebAuthn registration admits a reader; secrets do not cross proxy', async t => {
  const f = await fixture(t); const session = await f.enroll();
  const response = await f.request('/private', { headers: { cookie: session, authorization: 'Bearer secret', 'x-human-gate-user': 'forged', 'x-forwarded-for': '1.1.1.1' } });
  assert.equal(response.status, 200); assert.equal(await response.text(), 'PRIVATE_ORIGIN_CONTENT');
  assert.equal(response.headers.get('set-cookie'), null); assert.match(response.headers.get('cache-control'), /no-store/);
  assert.equal(f.lastHeaders().cookie, undefined); assert.equal(f.lastHeaders().authorization, undefined);
  assert.equal(f.lastHeaders()['x-forwarded-for'], undefined); assert.equal(f.lastHeaders()['x-human-gate-user'], f.auth.id);
});
test('registration invitation is single-use and challenges cannot be replayed', async t => {
  const f = await fixture(t); const invite = f.store.invite('reader');
  const issued = await f.post('/_gate/register/options', { invite }); const options = await issued.json();
  const response = f.auth.register(options.challenge); const cookie = f.cookieOf(issued);
  assert.equal((await f.post('/_gate/register/verify', response, cookie)).status, 200);
  assert.equal((await f.post('/_gate/register/verify', response, cookie)).status, 403);
  assert.equal((await f.post('/_gate/register/options', { invite })).status, 403);
});
test('signed login works and requires user verification, expected origin, and challenge', async t => {
  const f = await fixture(t); await f.enroll();
  for (const options of [{}, { uv: false }, { originOverride: 'https://attacker.example' }]) {
    const issued = await f.post('/_gate/login/options', {}); const challenge = await issued.json();
    const response = await f.post('/_gate/login/verify', f.auth.login(challenge.challenge, options), f.cookieOf(issued));
    assert.equal(response.status, Object.keys(options).length ? 403 : 200);
  }
  const issued = await f.post('/_gate/login/options', {});
  assert.equal((await f.post('/_gate/login/verify', f.auth.login(token()), f.cookieOf(issued))).status, 403);
});
test('expired sessions and changed user agents fail closed', async t => {
  const f = await fixture(t); const session = await f.enroll();
  assert.equal((await f.request('/', { headers: { cookie: session, 'user-agent': 'changed' } })).status, 401);
  f.advance(301000);
  assert.equal((await f.request('/', { headers: { cookie: session } })).status, 401);
  assert.equal(f.hits(), 0);
});
test('revocation immediately invalidates access and login', async t => {
  const f = await fixture(t); const session = await f.enroll(); f.store.revoke(f.auth.id);
  assert.equal((await f.request('/', { headers: { cookie: session } })).status, 401);
  const issued = await f.post('/_gate/login/options', {}); const challenge = await issued.json();
  assert.equal((await f.post('/_gate/login/verify', f.auth.login(challenge.challenge), f.cookieOf(issued))).status, 403);
});
test('concurrent requests cannot exceed the per-session budget', async t => {
  const f = await fixture(t, { pagesPerSession: 2 }); const session = await f.enroll();
  const responses = await Promise.all(Array.from({ length: 6 }, () => f.request('/', { headers: { cookie: session } })));
  assert.equal(responses.filter(r => r.status === 200).length, 2); assert.equal(f.hits(), 2);
});
test('credential rate limit survives creating a new session', async t => {
  const f = await fixture(t, { requestsPerMinute: 1 }); const session = await f.enroll();
  assert.equal((await f.request('/', { headers: { cookie: session } })).status, 200);
  const other = f.store.session(f.auth.id, 'test-browser', 300);
  assert.equal((await f.request('/', { headers: { cookie: `hg_session=${other}` } })).status, 429);
  assert.equal(f.hits(), 1);
});
test('wrong origin, missing Origin, forged Host, and cross-site requests fail', async t => {
  const f = await fixture(t);
  assert.equal((await f.post('/_gate/login/options', {}, null, { origin: 'https://evil.example' })).status, 403);
  assert.equal((await f.request('/_gate/login/options', { method: 'POST', body: '{}', headers: { 'content-type': 'application/json' } })).status, 403);
  const wrongHost = await new Promise((resolve, reject) => {
    http.get(f.config.origin, { headers: { host: 'evil.example' } }, response => { response.resume(); resolve(response.statusCode); }).on('error', reject);
  });
  assert.equal(wrongHost, 421);
  assert.equal((await f.request('/', { headers: { 'sec-fetch-site': 'cross-site' } })).status, 403);
  assert.equal(f.hits(), 0);
});
test('mutating methods, redirects and oversized auth bodies are rejected', async t => {
  const f = await fixture(t); const session = await f.enroll();
  assert.equal((await f.request('/', { method: 'POST', headers: { cookie: session } })).status, 405);
  assert.equal((await f.request('/redirect', { headers: { cookie: session } })).status, 502);
  assert.equal((await f.post('/_gate/login/options', { data: 'x'.repeat(20000) })).status, 413);
});
test('tampered signatures are rejected and consume the challenge', async t => {
  const f = await fixture(t); await f.enroll();
  const issued = await f.post('/_gate/login/options', {}); const challenge = await issued.json();
  const response = f.auth.login(challenge.challenge); response.response.signature = token();
  assert.equal((await f.post('/_gate/login/verify', response, f.cookieOf(issued))).status, 403);
  assert.equal((await f.post('/_gate/login/verify', f.auth.login(challenge.challenge), f.cookieOf(issued))).status, 403);
});
test('logout revokes server-side session; audit avoids sensitive content', async t => {
  const f = await fixture(t); const session = await f.enroll();
  assert.equal((await f.post('/_gate/logout', {}, session)).status, 200);
  assert.equal((await f.request('/?secret=do-not-log', { headers: { cookie: session } })).status, 401);
  assert.doesNotMatch(JSON.stringify(f.audit), /do-not-log|hg_session|test-reader/);
});
test('production configuration requires HTTPS', () => {
  assert.throws(() => configFromEnv({ PUBLIC_ORIGIN: 'http://example.com' }), /HTTPS/);
  assert.throws(() => configFromEnv({ SESSION_SECONDS: '-1' }), /SESSION_SECONDS/);
  assert.equal(configFromEnv({ PUBLIC_ORIGIN: 'https://private.example' }).secure, true);
});
