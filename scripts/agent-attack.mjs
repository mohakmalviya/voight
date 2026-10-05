// Automated browsers that try to pass the human check by really pressing and holding the button.
// Headed variants open real windows, so run this on a desktop (or under xvfb), not in CI.
import http from 'node:http';
import { once } from 'node:events';
import { chromium } from './browser-runtime.mjs';
import { loadAssets } from '../src/main.mjs';
import { configFromEnv } from '../src/config.mjs';
import { Store } from '../src/store.mjs';
import { createGateway } from '../src/gateway.mjs';

const origin = http.createServer((req, res) => {
  res.setHeader('content-type', 'text/html; charset=utf-8');
  res.end(`<!doctype html><title>Article ${req.url}</title><h1>Protected article</h1>`);
}).listen(0, '127.0.0.1');
await once(origin, 'listening');
const config = { ...configFromEnv({ MODE: 'public', CHALLENGE_DIFFICULTY: '12', SANDBOX_CHECK: 'enforce' }), upstream: `http://127.0.0.1:${origin.address().port}` };
const store = new Store(':memory:');
// Every address here is loopback, so a datacenter address is simulated by switching this on for one variant.
const cloud = { datacenter: false, has() { return this.datacenter; } };
let verdict = [];
const audit = event => { if (['human_pass_issued', 'sandbox_detected', 'automation_detected', 'human_check_failed'].includes(event.reason)) verdict = event.automationSignals; };
const gateway = createGateway({ config, store, assets: await loadAssets(), cloud, audit }).listen(0, '127.0.0.1');
await once(gateway, 'listening');
config.origin = `http://localhost:${gateway.address().port}`;

const HIDE = ['--disable-blink-features=AutomationControlled'];
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
// Playwright's own mouse.move: straight lines in identical steps.
const glide = async (page, x, y) => { await page.mouse.move(x - 300, y - 120, { steps: 10 }); await page.mouse.move(x, y, { steps: 25 }); };
// One jump onto the button, the way agent click tools move.
const jump = (page, x, y) => page.mouse.move(x, y);
// A curved, eased path with jitter, one step per frame: what a determined bot author would write.
const curve = async (page, x, y) => {
  const [sx, sy, cx, cy] = [x - 380, y - 160, x - 120, y + 90];
  for (let i = 1; i <= 40; i++) {
    const t = 1 - (1 - i / 40) ** 3, u = 1 - t;
    await page.mouse.move(u * u * sx + 2 * u * t * cx + t * t * x + (Math.random() - 0.5) * 1.6, u * u * sy + 2 * u * t * cy + t * t * y + (Math.random() - 0.5) * 1.6);
    await sleep(14 + Math.random() * 6);
  }
};
// What stealth plugins do: report a real GPU's name and make the patched getter look native.
const FAKE_GPU = () => {
  const real = WebGLRenderingContext.prototype.getParameter, toString = Function.prototype.toString;
  const fake = function getParameter(name) { return name === 37446 ? 'ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Direct3D11 vs_5_0 ps_5_0, D3D11)' : real.call(this, name); };
  WebGLRenderingContext.prototype.getParameter = fake;
  Function.prototype.toString = function () { return this === fake ? 'function getParameter() { [native code] }' : toString.call(this); };
};
const SOFTWARE_GPU = ['--use-angle=swiftshader'];
const variants = [
  ['plain headless Playwright', { headless: true }, glide],
  ['headless, webdriver flag hidden', { headless: true, args: HIDE }, glide],
  ['headless, flag hidden, ordinary user agent', { headless: true, args: HIDE, userAgent: UA }, glide],
  ['real window, flag hidden', { headless: false, args: HIDE }, glide],
  ['real window, flag hidden, agent-style jump', { headless: false, args: HIDE }, jump],
  ['real window, flag hidden, faked human curve', { headless: false, args: HIDE }, curve],
  ['… plus software GPU, like a cloud server', { headless: false, args: [...HIDE, ...SOFTWARE_GPU] }, curve],
  ['… plus software GPU with a faked GPU name', { headless: false, args: [...HIDE, ...SOFTWARE_GPU], init: FAKE_GPU }, curve],
  ['… from a datacenter address (simulated)', { headless: false, args: HIDE, datacenter: true }, curve],
  ['installed Edge, real window, faked curve', { headless: false, args: HIDE, channel: 'msedge', viewport: null }, curve],
];

const results = [];
try {
  for (const [name, { headless, args = [], userAgent, init, datacenter = false, channel, viewport }, move] of variants) {
    const browser = await chromium.launch({ headless, args, channel }).catch(() => null);
    if (!browser) { results.push({ variant: name, result: 'skipped', message: `${channel} is not installed` }); continue; }
    cloud.datacenter = datacenter; verdict = [];
    try {
      const context = await browser.newContext({ ...(userAgent ? { userAgent } : {}), ...(viewport === null ? { viewport: null } : {}) });
      if (init) await context.addInitScript(init);
      const page = await context.newPage();
      await page.goto(`${config.origin}/article/1`);
      await page.waitForFunction(() => !document.querySelector('#hold').disabled, null, { timeout: 30000 });
      const box = await page.locator('#hold').boundingBox();
      await move(page, box.x + box.width / 2, box.y + box.height / 2);
      await page.mouse.down(); await sleep(2000); await page.mouse.up();
      await page.waitForFunction(() => document.title.startsWith('Article') || document.querySelector('#human-heading')?.textContent === 'Check stopped.', null, { timeout: 15000 }).catch(() => {});
      const title = await page.title();
      const sandbox = verdict.filter(note => !/^(pointer|moves):/.test(note)).join(' ');
      results.push({ variant: name, result: title.startsWith('Article') ? 'GOT IN' : 'stopped', signals: sandbox, message: title.startsWith('Article') ? '' : (await page.locator('#status').textContent()).slice(0, 60) });
    } finally { await browser.close(); }
  }
} finally { gateway.close(); origin.close(); store.close(); }
console.table(results);
