import test from 'node:test';
import assert from 'node:assert/strict';
import { clientAddress, networkPrefix, parseCIDR, parseAddress } from '../src/network.mjs';
import { configFromEnv } from '../src/config.mjs';

test('client address walks X-Forwarded-For only through trusted proxies', () => {
  const trusted = ['10.0.0.0/8', '127.0.0.1'].map(parseCIDR);
  assert.equal(clientAddress('127.0.0.1', '9.9.9.9, 203.0.113.5, 10.2.3.4', trusted), '203.0.113.5');
  assert.equal(clientAddress('198.51.100.1', '203.0.113.5', trusted), '198.51.100.1');
  assert.equal(clientAddress('10.0.0.1', 'not-an-ip', trusted), '10.0.0.1');
  assert.equal(clientAddress('10.0.0.1', undefined, trusted), '10.0.0.1');
  assert.equal(clientAddress('::ffff:127.0.0.1', '203.0.113.5:4431', trusted), '203.0.113.5');
  assert.equal(clientAddress('127.0.0.1', '[2001:db8::1]:443', trusted), '2001:db8:0:0:0:0:0:1');
  assert.equal(clientAddress('127.0.0.1', '203.0.113.5', []), '127.0.0.1');
  assert.equal(clientAddress(undefined, '203.0.113.5', trusted), 'unknown');
});

test('IPv6 networks group by /64 and IPv4-mapped addresses equal IPv4', () => {
  assert.equal(networkPrefix('2001:db8:1:2:3:4:5:6'), '2001:db8:1:2::/64');
  assert.equal(networkPrefix('2001:db8:1:2::9'), '2001:db8:1:2::/64');
  assert.equal(networkPrefix('::ffff:192.0.2.1'), '192.0.2.1');
  assert.equal(networkPrefix('fe80::1%eth0'), 'fe80:0:0:0::/64');
  assert.equal(networkPrefix('garbage'), 'unknown');
  assert.deepEqual(parseAddress('::'), { version: 6, value: 0n });
});

test('trusted proxy configuration is validated', () => {
  assert.throws(() => parseCIDR('10.0.0.0/33'), /TRUSTED_PROXIES/);
  assert.throws(() => parseCIDR('example.com'), /TRUSTED_PROXIES/);
  assert.throws(() => parseCIDR('10.0.0.0/8/1'), /TRUSTED_PROXIES/);
  assert.throws(() => configFromEnv({ TRUSTED_PROXIES: '10.0.0.0/8, nope' }), /TRUSTED_PROXIES/);
  assert.equal(configFromEnv({ TRUSTED_PROXIES: '10.0.0.0/8, ::1' }).trustedProxies.length, 2);
});

test('mode selects defaults and rejects unknown values', () => {
  assert.equal(configFromEnv({}).mode, 'public');
  assert.ok(configFromEnv({}).resourcesPerWindow > configFromEnv({ MODE: 'private' }).resourcesPerWindow);
  assert.equal(configFromEnv({ MODE: 'private', RESOURCES_PER_WINDOW: '7' }).resourcesPerWindow, 7);
  assert.throws(() => configFromEnv({ MODE: 'stealth' }), /MODE/);
  assert.throws(() => configFromEnv({ BAN_SECONDS: '600', MAX_BAN_SECONDS: '60' }), /MAX_BAN_SECONDS/);
});
