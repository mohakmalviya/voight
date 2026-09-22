import test from 'node:test';
import assert from 'node:assert/strict';
import { Store, digest } from '../src/store.mjs';
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
