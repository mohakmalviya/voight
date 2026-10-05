import assert from 'node:assert/strict';
import { mkdir, readFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { chromium } from './browser-runtime.mjs';

const [input = 'dist/human-gate-demo.html', artifactDirectory = 'dist/showcase-artifacts'] = process.argv.slice(2);
const artifacts = resolve(artifactDirectory); await mkdir(artifacts, { recursive: true });
const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, recordVideo: { dir: fileURLToPath(new URL('../.cache/showcase-video/', import.meta.url)), size: { width: 1280, height: 900 } } });
  const page = await context.newPage(), video = page.video(), errors = [], network = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', request => { if (/^https?:/.test(request.url())) network.push(request.url()); });
  await context.route(/^https?:/, route => route.abort());
  await page.goto(pathToFileURL(resolve(input)).href);
  assert.equal(await page.title(), 'Human Gate — Access on your terms');
  assert.equal(await page.locator('#origin-count').textContent(), '0');
  await page.screenshot({ path: join(artifacts, 'showcase-desktop.png') });
  await page.waitForTimeout(1800);
  await page.getByRole('link', { name: /Explore the evidence/ }).click(); await page.waitForTimeout(1000);
  await page.locator('#evidence').screenshot({ path: join(artifacts, 'showcase-evidence.png') });
  for (const id of ['webdriver', 'observe', 'masked']) {
    await page.locator(`[data-case="${id}"]`).click(); await page.waitForTimeout(1500);
  }
  assert.equal(await page.locator('#outcome-title').textContent(), 'Automation was admitted.');
  assert.equal(await page.locator('#origin-count').textContent(), '4');
  await page.locator('#extraction-tab').click();
  assert.equal(await page.locator('#extraction-rows tr').count(), 6);
  assert.equal(await page.locator('#browser-panel').isVisible(), false);
  await page.waitForTimeout(1800);
  const downloadPromise = page.waitForEvent('download'); await page.locator('#download').click();
  const download = await downloadPromise; await download.saveAs(join(artifacts, 'human-gate-evidence.json'));
  const exported = JSON.parse(await readFile(join(artifacts, 'human-gate-evidence.json'), 'utf8'));
  assert.equal(exported.browser.scenarios.length, 4); assert.equal(exported.http.scenarios.length, 6);
  await page.locator('#extraction-tab').focus(); await page.keyboard.press('Home');
  assert.equal(await page.locator('#browser-tab').getAttribute('aria-selected'), 'true');
  await page.locator('[data-case="headless"]').click();
  await page.locator('#limits-title').scrollIntoViewIfNeeded(); await page.waitForTimeout(1800);
  assert.deepEqual(errors, []); assert.deepEqual(network, []);
  await context.close(); await video.saveAs(join(artifacts, 'human-gate-walkthrough.webm')); await video.delete();
  const mobile = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, deviceScaleFactor: 1 });
  const phone = await mobile.newPage(); await phone.goto(pathToFileURL(resolve(input)).href);
  assert.equal(await phone.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
  await phone.screenshot({ path: join(artifacts, 'showcase-mobile.png') });
  await phone.getByRole('link', { name: /Explore the evidence/ }).click();
  await phone.locator('[data-case="masked"]').click();
  assert.equal(await phone.locator('#outcome-title').textContent(), 'Automation was admitted.');
  await phone.locator('#evidence').screenshot({ path: join(artifacts, 'showcase-mobile-evidence.png') });
  await phone.locator('#extraction-tab').click();
  assert.equal(await phone.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
  await mobile.close();
  console.log('Showcase checks passed: desktop/mobile, evidence controls, keyboard tabs, JSON export, no network requests.');
} finally { await browser.close(); }
