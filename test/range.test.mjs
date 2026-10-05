import test from 'node:test';
import assert from 'node:assert/strict';
import { createFixture } from './fixture.mjs';
import { boundedRange } from '../src/gateway.mjs';

const FILE = Buffer.from(Array.from({ length: 100 }, (_, i) => i));
// A minimal origin that serves FILE with single byte-range support, like Apache or nginx.
function origin(req, res) {
  res.setHeader('content-type', 'video/mp4'); res.setHeader('accept-ranges', 'bytes'); res.setHeader('etag', '"v1"');
  const match = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range ?? '');
  if (!match || (req.headers['if-range'] && req.headers['if-range'] !== '"v1"')) { res.setHeader('content-length', FILE.length); return res.end(FILE); }
  let start = match[1] === '' ? FILE.length - Number(match[2]) : Number(match[1]);
  let end = match[1] === '' || match[2] === '' ? FILE.length - 1 : Math.min(Number(match[2]), FILE.length - 1);
  start = Math.max(start, 0);
  if (start >= FILE.length || end < start) { res.writeHead(416, { 'content-range': `bytes */${FILE.length}` }); return res.end(); }
  res.writeHead(206, { 'content-range': `bytes ${start}-${end}/${FILE.length}`, 'content-length': end - start + 1 });
  res.end(FILE.subarray(start, end + 1));
}
async function fixture(t, maxResponseBytes) {
  const f = await createFixture({ maxResponseBytes }, origin, undefined, { MODE: 'public', TRUSTED_PROXIES: '127.0.0.1', HUMAN_CHECK: 'off' });
  t.after(f.close); return f;
}
async function get(f, headers) {
  const response = await f.request('/clip.mp4', { headers: { 'x-forwarded-for': '203.0.113.5', ...headers } });
  return { status: response.status, headers: response.headers, body: Buffer.from(await response.arrayBuffer()), sent: f.lastHeaders() };
}

test('byte ranges reach the origin and come back as partial content', async t => {
  const f = await fixture(t, 1000);
  const slice = await get(f, { range: 'bytes=10-19' });
  assert.equal(slice.status, 206); assert.equal(slice.sent.range, 'bytes=10-19');
  assert.equal(slice.headers.get('content-range'), 'bytes 10-19/100');
  assert.equal(slice.headers.get('content-length'), '10'); assert.equal(slice.headers.get('accept-ranges'), 'bytes');
  assert.deepEqual(slice.body, FILE.subarray(10, 20));

  const whole = await get(f, {});
  assert.equal(whole.status, 200); assert.equal(whole.sent.range, undefined); assert.equal(whole.headers.get('accept-ranges'), 'bytes');
  const changed = await get(f, { range: 'bytes=10-19', 'if-range': '"old"' });
  assert.equal(changed.status, 200); assert.deepEqual(changed.body, FILE); // A changed file is sent whole, never stitched.
  const beyond = await get(f, { range: 'bytes=500-' });
  assert.equal(beyond.status, 416); assert.equal(beyond.headers.get('content-range'), 'bytes */100');
  const multiple = await get(f, { range: 'bytes=0-1,5-6' });
  assert.equal(multiple.status, 200); assert.equal(multiple.sent.range, undefined); // Multipart ranges are not forwarded.
});

test('files larger than the response limit are served in slices instead of failing', async t => {
  const f = await fixture(t, 40);
  assert.equal((await get(f, {})).status, 502); // A plain full download is still capped.
  const parts = [];
  for (let next = 0; next < FILE.length;) {
    const part = await get(f, { range: `bytes=${next}-` });
    assert.equal(part.status, 206); assert.ok(part.body.length <= 40);
    parts.push(part.body); next = Number(/bytes \d+-(\d+)\//.exec(part.headers.get('content-range'))[1]) + 1;
  }
  assert.equal(parts.length, 3); assert.deepEqual(Buffer.concat(parts), FILE);
  assert.equal((await get(f, { range: 'bytes=-90' })).sent.range, 'bytes=-40');
  assert.equal(f.store.bans().length, 0);
});

test('range bounding keeps each slice within the limit and rejects anything else', () => {
  assert.equal(boundedRange('bytes=0-', 100), 'bytes=0-99');
  assert.equal(boundedRange('bytes=50-60', 100), 'bytes=50-60');
  assert.equal(boundedRange('bytes=50-5000', 100), 'bytes=50-149');
  assert.equal(boundedRange('bytes=-500', 100), 'bytes=-100');
  assert.equal(boundedRange(' bytes=7-8 ', 100), 'bytes=7-8');
  for (const bad of [undefined, '', 'bytes=-', 'bytes=0-1,4-5', 'items=0-5', 'bytes=a-b', 'bytes=1234567890123456-']) assert.equal(boundedRange(bad, 100), null);
});
