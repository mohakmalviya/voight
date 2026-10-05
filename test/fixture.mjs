// Loopback-only evaluation harness. No production authentication bypass.
import assert from 'node:assert/strict';
import http from 'node:http';
import { once, EventEmitter } from 'node:events';
import { Store } from '../src/store.mjs';
import { createGateway } from '../src/gateway.mjs';
import { configFromEnv } from '../src/config.mjs';
import { authenticator } from './authenticator.mjs';

export async function createFixture(overrides = {}, originHandler, assets = { '/_gate/index.html': { body: '<h1>Admission required</h1>', type: 'text/html' } }) {
  let hits = 0, lastHeaders, time = Date.now();
  const upstream = http.createServer((req, res) => {
    hits++; lastHeaders = req.headers;
    if (originHandler) return originHandler(req, res);
    if (req.url === '/redirect') { res.writeHead(302, { location: 'https://example.com/' }); return res.end(); }
    res.setHeader('set-cookie', 'hg_session=attacker'); res.setHeader('cache-control', 'public');
    res.end('PRIVATE_ORIGIN_CONTENT');
  }).listen(0, '127.0.0.1'); await once(upstream, 'listening');
  const store = new Store(':memory:', () => time);
  const config = { ...configFromEnv({}), upstream: `http://127.0.0.1:${upstream.address().port}`, ...overrides };
  const audit = [], events = new EventEmitter();
  const gateway = createGateway({ config, store, assets, audit: event => { audit.push(event); events.emit('decision', event); } }).listen(0, '127.0.0.1');
  await once(gateway, 'listening'); config.origin = `http://localhost:${gateway.address().port}`;
  const headers = { 'user-agent': 'test-browser' };
  const request = (path = '/', init = {}) => fetch(`${config.origin}${path}`, { ...init, headers: { ...headers, ...init.headers }, redirect: 'manual' });
  const post = (path, body, cookie, extra = {}) => request(path, { method: 'POST', headers: { origin: config.origin, 'content-type': 'application/json', ...(cookie ? { cookie } : {}), ...extra }, body: JSON.stringify(body) });
  const auth = authenticator(config.rpID, config.origin);
  const cookieOf = response => response.headers.get('set-cookie')?.split(';')[0];
  async function enroll() {
    const options = await post('/_gate/register/options', { invite: store.invite('test-reader') });
    assert.equal(options.status, 200); const challenge = await options.json();
    const response = await post('/_gate/register/verify', auth.register(challenge.challenge), cookieOf(options));
    assert.equal(response.status, 200, await response.clone().text()); await response.text();
    return cookieOf(response);
  }
  async function login() {
    const options = await post('/_gate/login/options', {});
    assert.equal(options.status, 200); const challenge = await options.json();
    const response = await post('/_gate/login/verify', auth.login(challenge.challenge), cookieOf(options));
    assert.equal(response.status, 200, await response.clone().text()); await response.text();
    return cookieOf(response);
  }
  async function close() {
    gateway.closeAllConnections(); upstream.closeAllConnections();
    await Promise.all([new Promise(r => gateway.close(r)), new Promise(r => upstream.close(r))]);
    // Allow aborted asynchronous handlers to release their resources before closing SQLite.
    await new Promise(resolve => setImmediate(resolve)); store.close();
  }
  return { store, config, auth, request, post, enroll, login, cookieOf, audit, events, close,
    hits: () => hits, lastHeaders: () => lastHeaders, advance: ms => { time += ms; } };
}
