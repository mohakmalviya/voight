import test from 'node:test';
import assert from 'node:assert/strict';
import { Store, digest } from '../src/store.mjs';
import { configFromEnv } from '../src/config.mjs';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
test('expired and consumed challenges are unusable; invites expire', () => {
  let now = 0; const store = new Store(':memory:', () => now);
  try {
    const challenge = store.challenge({ test: true }); const invite = store.invite('reader', 1);
    now = 121000;
    assert.equal(store.takeChallenge(challenge), null); assert.equal(store.getInvite(invite), undefined);
    store.prune(); assert.equal(store.db.prepare('SELECT count(*) AS n FROM challenges').get().n, 0);
  } finally { store.close(); }
});
test('failed enrollment transaction preserves invite; duplicate credential cannot consume another invite', () => {
  const store = new Store(':memory:');
  try {
    const first = store.invite('first'); const second = store.invite('second');
    const credential = { id: 'credential', publicKey: new Uint8Array([1]), counter: 0 };
    store.enroll(digest(first), 'first', credential);
    assert.throws(() => store.enroll(digest(second), 'second', credential));
    assert.equal(store.getInvite(second).label, 'second');
  } finally { store.close(); }
});

function approved(store, id = 'reader') {
  store.enroll(digest(store.invite(id)), id, { id, publicKey: new Uint8Array([1]), counter: 0 });
}

test('byte windows expire per bucket and route windows track the last visit', () => {
  let now = 100;
  const store = new Store(':memory:', () => now);
  const config = { ...configFromEnv({}), bytesPerWindow: 10, resourcesPerWindow: 1, extractionWindowSeconds: 60 };
  try {
    approved(store);
    assert.equal(store.chargeBytes('reader', 6, config), null);
    assert.equal(store.beginResource('reader', '/a?private=1', config), null);
    now = 30100;
    assert.equal(store.chargeBytes('reader', 4, config), null);
    assert.equal(store.beginResource('reader', '/a?private=1', config)?.reason, 'byte_budget');
    assert.equal(store.chargeBytes('reader', 1, config)?.reason, 'byte_budget');
    now = 60999; // The first bucket is held until 61,000, never rounded down.
    assert.equal(store.chargeBytes('reader', 1, config)?.reason, 'byte_budget');
    now = 61000;
    assert.equal(store.usage()[0].bytes, 4);
    assert.equal(store.chargeBytes('reader', 5, config), null);
    assert.equal(store.beginResource('reader', '/a?private=1', config), null);
    now = 80000;
    assert.equal(store.beginResource('reader', '/a?private=1', config), null); // Extends this resource only.
    now = 121001;
    assert.equal(store.beginResource('reader', '/b', config)?.reason, 'resource_budget');
    now = 140001;
    assert.equal(store.beginResource('reader', '/b', config), null);
    store.prune();
    assert.equal(store.db.prepare('SELECT COUNT(*) AS n FROM byte_usage').get().n, 0);
    assert.equal(store.db.prepare('SELECT COUNT(*) AS n FROM resource_usage').get().n, 1);
    assert.doesNotMatch(JSON.stringify(store.db.prepare('SELECT * FROM resource_usage').all()), /private|\/b/);
  } finally { store.close(); }
});

test('separate credentials have separate extraction budgets', () => {
  const store = new Store(':memory:');
  const config = { ...configFromEnv({}), bytesPerWindow: 5, resourcesPerWindow: 1 };
  try {
    approved(store, 'first'); approved(store, 'second');
    assert.equal(store.beginResource('first', '/a', config), null);
    assert.equal(store.chargeBytes('first', 5, config), null);
    assert.equal(store.beginResource('first', '/b', config)?.reason, 'byte_budget');
    assert.equal(store.beginResource('second', '/b', config), null);
    assert.equal(store.chargeBytes('second', 5, config), null);
    store.revoke('second');
    assert.equal(store.chargeBytes('second', 1, config)?.reason, 'credential_revoked');
    assert.throws(() => store.chargeBytes('first', -1, config), /Invalid/);
  } finally { store.close(); }
});

test('existing credential databases upgrade additively and usage survives reopen across connections', () => {
  const directory = mkdtempSync(join(tmpdir(), 'human-gate-store-'));
  const path = join(directory, 'gate.sqlite');
  const legacy = new DatabaseSync(path);
  legacy.exec(`CREATE TABLE credentials (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, label TEXT NOT NULL, key TEXT NOT NULL, counter INTEGER NOT NULL, transports TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
    INSERT INTO credentials VALUES('existing','existing','Existing reader','AQ',0,'[]',0);`);
  legacy.close();
  const config = { ...configFromEnv({}), bytesPerWindow: 10, resourcesPerWindow: 1 };
  let first, second;
  try {
    first = new Store(path); second = new Store(path);
    assert.equal(first.list()[0].label, 'Existing reader');
    assert.equal(first.beginResource('existing', '/secret?id=1', config), null);
    assert.equal(first.chargeBytes('existing', 6, config), null);
    assert.equal(second.chargeBytes('existing', 5, config)?.reason, 'byte_budget');
    assert.equal(second.chargeBytes('existing', 3, config), null);
    first.close(); first = new Store(path);
    assert.equal(first.usage()[0].bytes, 9);
    assert.equal(first.beginResource('existing', '/secret?id=1', config), null); // Persistent HMAC key.
    assert.equal(first.beginResource('existing', '/secret?id=2', config)?.reason, 'resource_budget');
    first.session('existing', 'new-browser', 300);
    assert.equal(first.chargeBytes('existing', 2, config)?.reason, 'byte_budget');
  } finally {
    first?.close(); second?.close();
    // This path is created exclusively by mkdtemp above and contains only this test database.
    rmSync(directory, { recursive: true, force: true });
  }
});
