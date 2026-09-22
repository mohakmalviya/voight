// Controlled loopback evaluation only. The authenticator is a scripted test fixture.
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { createFixture } from '../test/fixture.mjs';

const cases = [
  { name: 'unapproved HTTP extraction', count: 12, unapproved: true, expected: 0, path: i => `/record?id=${i}` },
  { name: 'approved scripted reading within limits', count: 6, expected: 6, path: i => `/article/${i}` },
  { name: 'approved query enumeration', count: 20, expected: 5, config: { resourcesPerWindow: 5 }, path: i => `/record?id=${i}` },
  { name: 'approved session rotation', count: 8, expected: 3, rotate: true, config: { resourcesPerWindow: 3 }, path: i => `/record?id=${i}` },
  { name: 'approved repeated download', count: 12, expected: 4, payloadBytes: 2048, config: { bytesPerWindow: 8192 }, path: () => '/export' },
  { name: 'approved parallel saturation', count: 8, expected: 2, parallel: true, config: { maxConcurrentRequests: 2 }, path: () => '/article' },
];

async function evaluate(scenario) {
  const payload = Buffer.alloc(scenario.payloadBytes ?? 1024, 'p');
  const held = [], occupied = Promise.withResolvers();
  const f = await createFixture({ requestsPerMinute: 100, pagesPerSession: 100, ...scenario.config }, (_, res) => {
    if (!scenario.parallel) return res.end(payload);
    held.push(res); if (held.length === 2) occupied.resolve();
  });
  try {
    let session = scenario.unapproved ? null : await f.enroll();
    const observations = [];
    const issue = async index => {
      const start = performance.now();
      const response = await f.request(scenario.path(index), { headers: session ? { cookie: session } : {}, signal: AbortSignal.timeout(5000) });
      const body = Buffer.from(await response.arrayBuffer());
      const allowed = response.status === 200;
      if (allowed) assert.deepEqual(body, payload); else assert.ok([401, 429].includes(response.status));
      return { status: response.status, protectedBytes: allowed ? body.length : 0, latencyMs: performance.now() - start };
    };
    if (scenario.parallel) {
      // Hold two transfers open, probe six more, then release. Avoid timing-dependent race assertions.
      const initial = Promise.all([issue(0), issue(1)]);
      await Promise.race([occupied.promise, initial.then(() => { throw new Error('Expected held upstream transfers'); })]);
      observations.push(...await Promise.all(Array.from({ length: scenario.count - 2 }, (_, i) => issue(i + 2))));
      for (const response of held) response.end(payload);
      observations.push(...await initial);
    } else {
      for (let i = 0; i < scenario.count; i++) {
        if (scenario.rotate && i) session = await f.login();
        observations.push(await issue(i));
      }
    }
    const allowed = observations.filter(result => result.status === 200).length;
    const protectedBytes = observations.reduce((sum, result) => sum + result.protectedBytes, 0);
    assert.equal(allowed, scenario.expected, scenario.name);
    assert.equal(f.hits(), scenario.expected, `${scenario.name}: upstream boundary`);
    assert.ok(protectedBytes <= f.config.bytesPerWindow);
    const latencies = observations.map(result => result.latencyMs).sort((a, b) => a - b);
    const percentile = fraction => Number(latencies[Math.ceil(latencies.length * fraction) - 1].toFixed(2));
    const reasons = {};
    for (const event of f.audit) if (!['challenge_issued', 'verified'].includes(event.reason)) reasons[event.reason] = (reasons[event.reason] ?? 0) + 1;
    return { name: scenario.name, requests: scenario.count, allowed, blocked: scenario.count - allowed, upstreamRequests: f.hits(), protectedBytes,
      p50Ms: percentile(0.5), p95Ms: percentile(0.95), decisions: reasons,
      limits: { windowSeconds: f.config.extractionWindowSeconds, bytes: f.config.bytesPerWindow, resources: f.config.resourcesPerWindow, concurrency: f.config.maxConcurrentRequests } };
  } finally { await f.close(); }
}

const args = process.argv.slice(2);
if (args.length && (args.length !== 2 || args[0] !== '--output')) throw new Error('Usage: npm run benchmark -- [--output <report.json>]');
const report = {
  generatedAt: new Date().toISOString(), node: process.versions.node,
  scope: 'Single-process loopback scripts with real WebAuthn verification and a software authenticator; controlled limits, not a human/bot classifier.',
  notMeasured: ['real humans and false rejection', 'browser agents and stealth automation', 'hardware passkeys', 'internet-scale throughput and DDoS'],
  scenarios: [],
};
for (const scenario of cases) report.scenarios.push(await evaluate(scenario));
const output = `${JSON.stringify(report, null, 2)}\n`;
if (args.length) { const path = resolve(args[1]); await mkdir(dirname(path), { recursive: true }); await writeFile(path, output); }
console.log(output.trimEnd());
