import http from 'node:http';
import { start } from '../src/main.mjs';
import { configFromEnv } from '../src/config.mjs';
const config = configFromEnv();
const target = new URL(config.upstream);
if (!['127.0.0.1', 'localhost'].includes(target.hostname) || target.protocol !== 'http:') throw new Error('Demo upstream must be HTTP loopback');
const origin = http.createServer((req, res) => {
  res.setHeader('content-type', 'text/html; charset=utf-8');
  res.end('<!doctype html><html lang="en"><meta charset="utf-8"><title>Protected content</title><h1>You are through the gate.</h1><p>This content was fetched only after server-side admission.</p><p>Refreshes and asset requests consume your access budget. Re-verification is required after your session expires.</p></html>');
});
await new Promise((resolve, reject) => { origin.once('error', reject); origin.listen(Number(target.port || 80), '127.0.0.1', resolve); });
const gateway = await start(config);
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { gateway.close(); origin.close(); gateway.closeIdleConnections(); origin.closeIdleConnections(); });
