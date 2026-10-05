import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve, join } from 'node:path';
import { chromium } from './browser-runtime.mjs';
import { loadAssets } from '../src/main.mjs';
import { createFixture } from '../test/fixture.mjs';

const args = process.argv.slice(2);
let outputPath, artifacts;
for (let i = 0; i < args.length; i += 2) {
  if (!args[i + 1] || !['--output', '--artifacts'].includes(args[i])) throw new Error('Use --output <report.json> and/or --artifacts <directory>');
  if (args[i] === '--output') outputPath = resolve(args[i + 1]); else artifacts = resolve(args[i + 1]);
}
if (artifacts) await mkdir(artifacts, { recursive: true });
const assets = await loadAssets();
const browser = await chromium.launch({ headless: true });
const cases = [
  { id: 'observe', name: 'Declared automation / observe', mode: 'observe', allowed: true, description: 'A real automated Chromium browser completes the production passkey interface. Observe mode records its signals.' },
  { id: 'headless', name: 'Declared browser / enforce', mode: 'enforce', allowed: false, description: 'The browser declares HeadlessChrome in its user agent. Enforce mode rejects access.' },
  { id: 'webdriver', name: 'WebDriver signal / enforce', mode: 'enforce', normalUA: true, allowed: false, description: 'An ordinary-looking user agent still reports navigator.webdriver=true. The registration attempt is rejected.' },
  { id: 'masked', name: 'Suppressed signals / enforce', mode: 'enforce', normalUA: true, masked: true, allowed: true, description: 'A controlled test hides both declarations. Automation gets through with an invitation and a virtual passkey; extraction budgets still apply.' },
];
const report = { generatedAt: new Date().toISOString(), browser: browser.version(), scope: 'Loopback-only Chromium with a virtual authenticator. All participants are automation; none are human controls.', humanFalseRejection: 'not measured', scenarios: [] };
try {
  for (const scenario of cases) {
    const originBody = '<!doctype html><html lang="en"><meta charset="utf-8"><title>Protected sample</title><link rel="icon" href="data:,"><h1>Protected sample document</h1><p>Only synthetic demonstration content is used in this benchmark.</p></html>';
    const f = await createFixture({ automationPolicy: scenario.mode, resourcesPerWindow: 3 }, (_, res) => { res.setHeader('content-type', 'text/html; charset=utf-8'); res.end(originBody); }, assets);
    const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, ...(scenario.normalUA ? { userAgent: `Mozilla/5.0 Chrome/${browser.version()} Safari/537.36` } : {}) });
    try {
      // Test instrumentation only; never injected by Human Gate or applied to third-party sites.
      if (scenario.masked) await context.addInitScript(() => Object.defineProperty(Navigator.prototype, 'webdriver', { get: () => false }));
      await context.route('**/*', route => new URL(route.request().url()).origin === f.config.origin ? route.continue() : route.abort());
      const page = await context.newPage(); page.setDefaultTimeout(10000);
      const pageErrors = []; page.on('pageerror', error => pageErrors.push(error.message));
      const cdp = await context.newCDPSession(page);
      await cdp.send('WebAuthn.enable');
      await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
      const initial = await page.goto(f.config.origin);
      assert.equal(initial.status(), scenario.id === 'headless' ? 403 : 401);
      if (scenario.id === 'observe' && artifacts) await page.screenshot({ path: join(artifacts, 'gate-desktop.png'), fullPage: true });
      // Gate assets stay readable even when a declaration is rejected, so visitors can get help.
      await page.goto(`${f.config.origin}/_gate/index.html`);
      await page.locator('summary').click();
      await page.locator('#invite').fill(f.store.invite('Browser evaluation'));
      const expectedEndpoint = scenario.allowed ? '/_gate/register/verify' : '/_gate/register/options';
      const resultPromise = page.waitForResponse(response => new URL(response.url()).pathname === expectedEndpoint && response.request().method() === 'POST');
      await page.locator('#enroll button').click();
      const result = await resultPromise; assert.equal(result.status(), scenario.allowed ? 200 : 403);
      let budgetBlocked = false;
      if (scenario.allowed) {
        await page.getByRole('heading', { name: 'Protected sample document' }).waitFor();
        // Exercise login as well as enrollment using the same resident browser passkey.
        await page.evaluate(async () => { await fetch('/_gate/logout', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }); });
        await page.goto(f.config.origin);
        const login = page.waitForResponse(response => new URL(response.url()).pathname === '/_gate/login/verify');
        await page.locator('#login').click(); assert.equal((await login).status(), 200);
        await page.getByRole('heading', { name: 'Protected sample document' }).waitFor();
        if (scenario.masked) {
          for (const id of [1, 2]) { const response = await page.goto(`${f.config.origin}/record?id=${id}`); assert.equal(response.status(), 200); }
          const blocked = await page.goto(`${f.config.origin}/record?id=3`); assert.equal(blocked.status(), 429);
          await page.getByRole('heading', { name: 'Access paused' }).waitFor(); budgetBlocked = true;
          if (artifacts) await page.screenshot({ path: join(artifacts, 'limit-desktop.png'), fullPage: true });
        }
      } else {
        await page.getByRole('status').filter({ hasText: 'reported automation' }).waitFor();
        assert.equal(f.hits(), 0);
      }
      assert.deepEqual(pageErrors, []);
      const evidence = [...new Set(f.audit.flatMap(event => event.automationSignals))];
      if (scenario.id === 'observe') assert.ok(evidence.includes('webdriver'));
      if (scenario.masked) assert.deepEqual(evidence, []);
      report.scenarios.push({ id: scenario.id, name: scenario.name, mode: scenario.mode, accessGranted: scenario.allowed, originRequests: f.hits(), signals: evidence, extractionBudgetStopped: budgetBlocked, description: scenario.description });
    } finally { await context.close(); await f.close(); }
  }
} finally { await browser.close(); }
const encoded = `${JSON.stringify(report, null, 2)}\n`;
if (outputPath) { await mkdir(dirname(outputPath), { recursive: true }); await writeFile(outputPath, encoded); }
console.log(encoded.trimEnd());
