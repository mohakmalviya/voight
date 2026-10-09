import test from 'node:test';
import assert from 'node:assert/strict';
import { createFixture } from './fixture.mjs';
import { configFromEnv } from '../src/config.mjs';
import { automationSignals, reportedWebdriver } from '../src/automation.mjs';

async function fixture(t, automationPolicy = 'observe') {
  const f = await createFixture({ automationPolicy }); t.after(f.close); return f;
}
async function options(f, report) {
  return f.post('/_gate/register/options', { invite: f.store.invite('reader'), clientSignals: report });
}
async function complete(f, issued) {
  const challenge = await issued.json();
  return f.post('/_gate/register/verify', f.auth.register(challenge.challenge), f.cookieOf(issued));
}

test('observe logs declared automation but still requires valid passkey admission', async t => {
  const f = await fixture(t);
  const issued = await options(f, { webdriver: true }); assert.equal(issued.status, 200);
  const verified = await complete(f, issued); assert.equal(verified.status, 200);
  const response = await f.request('/', { headers: { cookie: f.cookieOf(verified) } });
  assert.equal(response.status, 200); await response.text();
  assert.deepEqual(f.audit.find(e => e.reason === 'admitted').automationSignals, ['webdriver']);
  assert.equal(f.store.db.prepare('SELECT webdriver FROM session_signals').get().webdriver, 1);
});

test('enforce denies positive and missing reports before issuing a challenge', async t => {
  const f = await fixture(t, 'enforce');
  for (const report of [{ webdriver: true }, undefined, { webdriver: 'false' }, [], null]) {
    const response = await options(f, report); assert.equal(response.status, 403);
    assert.equal((await response.json()).error, report?.webdriver === true ? 'automation_declared' : 'automation_report_required');
  }
  assert.equal(f.store.db.prepare('SELECT COUNT(*) AS n FROM challenges').get().n, 0);
  assert.equal(f.hits(), 0);
});

test('a false report is not proof of humanity and never bypasses authentication', async t => {
  const f = await fixture(t, 'enforce');
  assert.equal((await f.request('/', { headers: { 'x-human': 'true' } })).status, 401);
  const issued = await options(f, { webdriver: false }); assert.equal(issued.status, 200);
  const verified = await complete(f, issued); assert.equal(verified.status, 200);
  const response = await f.request('/', { headers: { cookie: f.cookieOf(verified) } }); assert.equal(response.status, 200); await response.text();
  assert.equal(f.hits(), 1); // This is a script with a software authenticator, deliberately admitted.
});

test('enforce rechecks stored session reports after a policy change; missing legacy reports require login', async t => {
  const f = await fixture(t);
  const verified = await complete(f, await options(f, { webdriver: true }));
  f.config.automationPolicy = 'enforce';
  assert.equal((await f.request('/', { headers: { cookie: f.cookieOf(verified) } })).status, 403);
  const legacy = f.store.session(f.auth.id, 'test-browser', 300);
  assert.equal((await f.request('/', { headers: { cookie: `hg_session=${legacy}` } })).status, 401);
  assert.equal(f.hits(), 0);
});

test('a verify payload cannot replace the ceremony report and logout deletes stored signals', async t => {
  const f = await fixture(t);
  const issued = await options(f, { webdriver: true }); const pending = await issued.json();
  const response = await f.post('/_gate/register/verify', { ...f.auth.register(pending.challenge), clientSignals: { webdriver: false } }, f.cookieOf(issued));
  assert.equal(response.status, 200);
  assert.equal(f.store.db.prepare('SELECT webdriver FROM session_signals').get().webdriver, 1);
  await f.post('/_gate/logout', {}, f.cookieOf(response));
  assert.equal(f.store.db.prepare('SELECT COUNT(*) AS n FROM session_signals').get().n, 0);
});

test('off ignores and does not persist reports; expired sessions prune signal records', async t => {
  const f = await fixture(t, 'off');
  const verified = await complete(f, await options(f, { webdriver: true })); assert.equal(verified.status, 200);
  assert.equal(f.store.db.prepare('SELECT COUNT(*) AS n FROM session_signals').get().n, 0);
  assert.ok(f.audit.every(e => e.automationSignals.length === 0));
  f.store.session(f.auth.id, 'test-browser', 15, true); f.advance(16000); f.store.prune();
  assert.equal(f.store.db.prepare('SELECT COUNT(*) AS n FROM session_signals').get().n, 0);
});

test('declared user agents are denied without origin hits; gate assets and human-readable errors remain available', async t => {
  const f = await fixture(t, 'enforce');
  const headers = { 'user-agent': 'Mozilla/5.0 HeadlessChrome/153.0', accept: 'text/html' };
  const response = await f.request('/', { headers }); assert.equal(response.status, 403);
  assert.match(response.headers.get('content-type'), /text\/html/); assert.match(await response.text(), /Automated access is restricted/);
  assert.equal((await f.request('/_gate/index.html', { headers })).status, 200); assert.equal(f.hits(), 0);
  assert.doesNotMatch(JSON.stringify(f.audit), /Mozilla|HeadlessChrome/);
});

test('budget denial renders useful HTML and preserves JSON responses for programmatic callers', async t => {
  const f = await fixture(t); const cookie = await f.enroll(); f.config.resourcesPerWindow = 1;
  await (await f.request('/a', { headers: { cookie } })).text();
  const page = await f.request('/b', { headers: { cookie, accept: 'text/html' } });
  assert.equal(page.status, 429); assert.match(await page.text(), /Access paused/); assert.ok(Number(page.headers.get('retry-after')) > 0);
  const api = await f.request('/c', { headers: { cookie } }); assert.equal((await api.json()).error, 'resource_budget');
});

test('signal parsing is narrow and configuration rejects misspelled policy', () => {
  assert.deepEqual(automationSignals('HumanReader/1.0', false), []);
  assert.deepEqual(automationSignals('SomeHeadlessChromeExtension/1.0', false), []);
  assert.equal(reportedWebdriver({ clientSignals: { webdriver: 'true' } }), null);
  assert.throws(() => configFromEnv({ AUTOMATION_POLICY: 'enfroce' }), /AUTOMATION_POLICY/);
});
