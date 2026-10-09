import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
const args = process.argv.slice(2);
if (args.length && (args.length !== 2 || args[0] !== '--output')) throw new Error('Usage: npm run showcase -- [--output <demo.html>]');
const [template, css, js, http, browser] = await Promise.all([
  '../showcase/index.html', '../showcase/style.css', '../showcase/client.mjs', '../docs/benchmark-results.json', '../docs/browser-benchmark-results.json',
].map(path => readFile(new URL(path, import.meta.url), 'utf8')));
const reports = { http: JSON.parse(http), browser: JSON.parse(browser) };
if (reports.http.scenarios.length !== 6 || reports.browser.scenarios.length !== 4) throw new Error('Unexpected evidence shape; review the showcase before exporting');
const json = JSON.stringify(reports).replaceAll('<', '\\u003c').replaceAll('\u2028', '\\u2028').replaceAll('\u2029', '\\u2029');
const html = template.replace('/* SHOWCASE_CSS */', () => css).replace('/* EVIDENCE_JSON */', () => json).replace('/* SHOWCASE_JS */', () => js);
const destination = resolve(args[1] ?? 'dist/voight-demo.html');
await mkdir(dirname(destination), { recursive: true }); await writeFile(destination, html);
console.log(`Standalone demo written to ${destination}`);
