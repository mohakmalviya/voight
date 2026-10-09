import http from 'node:http';
import { start } from '../src/main.mjs';
import { configFromEnv } from '../src/config.mjs';
const config = configFromEnv();
const target = new URL(config.upstream);
if (!['127.0.0.1', 'localhost'].includes(target.hostname) || target.protocol !== 'http:') throw new Error('Demo upstream must be HTTP loopback');
const origin = http.createServer((req, res) => {
  res.setHeader('content-type', 'text/html; charset=utf-8');
  res.end(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Demo origin</title><h1>Demo origin: ${req.url}</h1><p>Mode: ${config.mode}. This page came from the origin through the gateway.</p><p>Every distinct URL spends part of your network's budget. Try <a href="/page?n=${Date.now()}">another page</a>.</p></html>`);
});
await new Promise((resolve, reject) => { origin.once('error', reject); origin.listen(Number(target.port || 80), '127.0.0.1', resolve); });
const gateway = await start(config);
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { gateway.close(); origin.close(); gateway.closeIdleConnections(); origin.closeIdleConnections(); });
