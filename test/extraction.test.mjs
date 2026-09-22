import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { gzipSync } from 'node:zlib';
import { configFromEnv } from '../src/config.mjs';
import { createFixture } from './fixture.mjs';

async function fixture(t, config, handler) {
  const f = await createFixture(config, handler); t.after(f.close); return f;
}
function decision(f, reason) {
  return new Promise(resolve => {
    const listener = event => { if (event.reason === reason) { f.events.off('decision', listener); resolve(event); } };
    f.events.on('decision', listener);
  });
}

test('query enumeration is bounded across real passkey logins and recovers after the rolling window', async t => {
  const f = await fixture(t, { resourcesPerWindow: 2, extractionWindowSeconds: 60, sessionSeconds: 300 });
  let session = await f.enroll();
  for (const path of ['/record?id=1', '/record?id=2']) {
    const r = await f.request(path, { headers: { cookie: session } }); assert.equal(r.status, 200); await r.text();
  }
  session = await f.login();
  const denied = await f.request('/record?id=3', { headers: { cookie: session } });
  assert.equal(denied.status, 429); assert.equal((await denied.json()).error, 'resource_budget');
  assert.equal(denied.headers.get('retry-after'), '60'); assert.equal(f.hits(), 2);
  const revisit = await f.request('/record?id=1', { headers: { cookie: session } }); assert.equal(revisit.status, 200); await revisit.text();
  f.advance(60001);
  const recovered = await f.request('/record?id=3', { headers: { cookie: session } }); assert.equal(recovered.status, 200); await recovered.text();
});

test('parallel transfers cannot overspend a credential byte budget through multiple sessions', async t => {
  const f = await fixture(t, { bytesPerWindow: 32, maxConcurrentRequests: 8 }, (_, res) => res.end('x'.repeat(16)));
  const sessions = [await f.enroll(), await f.login()];
  const responses = await Promise.all(Array.from({ length: 8 }, async (_, i) => {
    const response = await f.request('/same', { headers: { cookie: sessions[i % 2] } });
    return { status: response.status, body: await response.text() };
  }));
  assert.equal(responses.filter(r => r.status === 200).length, 2);
  assert.equal(responses.filter(r => r.status === 429).length, 6);
  assert.equal(responses.filter(r => r.status === 200).reduce((sum, r) => sum + r.body.length, 0), 32);
  const hits = f.hits();
  const next = await f.request('/next', { headers: { cookie: await f.login() } });
  assert.equal(next.status, 429); assert.equal((await next.json()).error, 'byte_budget'); assert.equal(f.hits(), hits);
  assert.equal(f.store.usage()[0].bytes, 32);
});

test('compressed bytes cannot disguise a larger decoded body', async t => {
  const f = await fixture(t, { bytesPerWindow: 100 }, (_, res) => {
    const body = gzipSync('PRIVATE'.repeat(1000));
    assert.ok(body.length < 100);
    res.writeHead(200, { 'content-encoding': 'gzip', 'content-length': body.length }); res.end(body);
  });
  const response = await f.request('/', { headers: { cookie: await f.enroll() } });
  assert.equal(response.status, 429); assert.equal(response.headers.get('content-encoding'), null);
  assert.equal((await response.json()).error, 'byte_budget'); assert.equal(f.store.usage()[0].bytes, 0);
});

test('a stream stops before an over-budget chunk and logs the incomplete response once', { timeout: 5000 }, async t => {
  let finishBody;
  const f = await fixture(t, { bytesPerWindow: 10 }, (_, res) => { res.write('123456'); finishBody = () => res.end('789012'); });
  const logged = decision(f, 'byte_budget');
  const response = await f.request('/secret?token=do-not-log', { headers: { cookie: await f.enroll() } });
  const reader = response.body.getReader(); const first = await reader.read();
  assert.equal(Buffer.from(first.value).toString(), '123456'); finishBody();
  await assert.rejects(reader.read());
  const event = await logged;
  assert.equal(event.completed, false); assert.equal(event.chargedBytes, 6); assert.equal(event.status, 200);
  assert.equal(f.audit.filter(e => e.reason === 'byte_budget').length, 1);
  assert.doesNotMatch(JSON.stringify(f.audit), /do-not-log|secret|test-reader|hg_session/);
});

test('concurrency is shared across sessions and released after completion', { timeout: 5000 }, async t => {
  const arrived = Promise.withResolvers();
  let held = true;
  const f = await fixture(t, { maxConcurrentRequests: 1 }, (_, res) => { if (held) arrived.resolve(res); else res.end('ready'); });
  const first = await f.enroll(), second = await f.login();
  const pending = f.request('/slow', { headers: { cookie: first } });
  const upstream = await arrived.promise;
  const denied = await f.request('/other', { headers: { cookie: second } });
  assert.equal(denied.status, 429); assert.equal((await denied.json()).error, 'parallel_limit');
  assert.equal(denied.headers.get('retry-after'), '1'); assert.equal(f.hits(), 1);
  held = false; upstream.end('done'); assert.equal(await (await pending).text(), 'done');
  const next = await f.request('/other', { headers: { cookie: second } }); assert.equal(next.status, 200); await next.text();
});

test('disconnect before upstream headers cancels work, logs it, and releases the slot', { timeout: 5000 }, async t => {
  const arrived = Promise.withResolvers();
  let held = true;
  const f = await fixture(t, { maxConcurrentRequests: 1 }, (_, res) => { if (held) arrived.resolve(res); else res.end('ready'); });
  const session = await f.enroll(), abort = new AbortController();
  const pending = f.request('/slow', { headers: { cookie: session }, signal: abort.signal });
  const upstream = await arrived.promise; const closed = once(upstream, 'close');
  const logged = decision(f, 'client_closed');
  abort.abort(); await assert.rejects(pending); await closed;
  assert.equal((await logged).completed, false);
  held = false;
  const next = await f.request('/other', { headers: { cookie: session } }); assert.equal(next.status, 200); await next.text();
});

test('revocation during a transfer prevents the next chunk', { timeout: 5000 }, async t => {
  let finishBody;
  const f = await fixture(t, {}, (_, res) => { res.write('first'); finishBody = () => res.end('secret-after-revocation'); });
  const logged = decision(f, 'credential_revoked');
  const response = await f.request('/', { headers: { cookie: await f.enroll() } });
  const reader = response.body.getReader(); assert.equal(Buffer.from((await reader.read()).value).toString(), 'first');
  f.store.revoke(f.auth.id); finishBody(); await assert.rejects(reader.read());
  assert.equal((await logged).chargedBytes, 5);
});

test('response size errors release slots; HEAD consumes a resource but no body bytes', async t => {
  const f = await fixture(t, { maxResponseBytes: 3, maxConcurrentRequests: 1 }, (_, res) => res.end('large'));
  const session = await f.enroll();
  const response = await f.request('/large', { headers: { cookie: session } });
  assert.equal(response.status, 502); assert.equal((await response.json()).error, 'response_size');
  const head = await f.request('/metadata', { method: 'HEAD', headers: { cookie: session } });
  assert.equal(head.status, 200); assert.equal(await head.text(), '');
  const usage = f.store.usage()[0]; assert.equal(usage.bytes, 0); assert.equal(usage.resources, 2);
});

test('extraction settings reject unsafe or malformed values', () => {
  for (const env of [{ EXTRACTION_WINDOW_SECONDS: '0' }, { BYTES_PER_WINDOW: '-1' }, { RESOURCES_PER_WINDOW: '1.2' }, { MAX_CONCURRENT_REQUESTS: '0' }, { MAX_RESPONSE_BYTES: 'NaN' }]) {
    assert.throws(() => configFromEnv(env), /Invalid/);
  }
});
