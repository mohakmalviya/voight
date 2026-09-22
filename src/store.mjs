import { DatabaseSync } from 'node:sqlite';
import { createHash, randomBytes } from 'node:crypto';

export const token = () => randomBytes(32).toString('base64url');
export const digest = value => createHash('sha256').update(value).digest('hex');

export class Store {
  constructor(path, now = Date.now) {
    this.now = now;
    this.db = new DatabaseSync(path, { timeout: 5000 });
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS invites (hash TEXT PRIMARY KEY, label TEXT NOT NULL, expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS credentials (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, label TEXT NOT NULL, key TEXT NOT NULL, counter INTEGER NOT NULL, transports TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS challenges (hash TEXT PRIMARY KEY, payload TEXT NOT NULL, expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS sessions (hash TEXT PRIMARY KEY, credential_id TEXT NOT NULL REFERENCES credentials(id), ua TEXT NOT NULL, expires INTEGER NOT NULL, requests INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS limits (key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS session_expiry ON sessions(expires);`);
  }
  invite(label, seconds = 3600) {
    const value = token();
    this.db.prepare('INSERT INTO invites VALUES(?,?,?)').run(digest(value), label, this.now() + seconds * 1000);
    return value;
  }
  getInvite(value) { return this.db.prepare('SELECT * FROM invites WHERE hash=? AND expires>?').get(digest(value), this.now()); }
  challenge(payload) {
    const value = token();
    this.db.prepare('INSERT INTO challenges VALUES(?,?,?)').run(digest(value), JSON.stringify(payload), this.now() + 120000);
    return value;
  }
  takeChallenge(value) {
    const row = this.db.prepare('DELETE FROM challenges WHERE hash=? RETURNING *').get(digest(value));
    return row && row.expires > this.now() ? JSON.parse(row.payload) : null;
  }
  enroll(inviteHash, userID, credential) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.db.prepare('DELETE FROM invites WHERE hash=? AND expires>? RETURNING label').get(inviteHash, this.now());
      if (!row) throw new Error('Invitation expired or already used');
      this.db.prepare('INSERT INTO credentials(id,user_id,label,key,counter,transports) VALUES(?,?,?,?,?,?)').run(
        credential.id, userID, row.label, Buffer.from(credential.publicKey).toString('base64url'), credential.counter, JSON.stringify(credential.transports ?? []));
      this.db.exec('COMMIT');
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  credential(id) {
    const row = this.db.prepare('SELECT * FROM credentials WHERE id=? AND revoked=0').get(id);
    return row ? { ...row, publicKey: new Uint8Array(Buffer.from(row.key, 'base64url')), transports: JSON.parse(row.transports) } : null;
  }
  updateCounter(id, before, after) {
    return this.db.prepare('UPDATE credentials SET counter=? WHERE id=? AND counter=? AND revoked=0').run(after, id, before).changes === 1;
  }
  session(credentialID, ua, seconds) {
    const value = token();
    this.db.prepare('INSERT INTO sessions(hash,credential_id,ua,expires) VALUES(?,?,?,?)').run(digest(value), credentialID, digest(ua), this.now() + seconds * 1000);
    return value;
  }
  admit(value, ua, maxRequests) {
    // One atomic increment prevents concurrent requests exceeding the budget.
    return this.db.prepare(`UPDATE sessions SET requests=requests+1 WHERE hash=? AND ua=? AND expires>? AND requests<?
      AND EXISTS(SELECT 1 FROM credentials WHERE id=sessions.credential_id AND revoked=0) RETURNING credential_id`).get(digest(value), digest(ua), this.now(), maxRequests);
  }
  logout(value) { this.db.prepare('DELETE FROM sessions WHERE hash=?').run(digest(value)); }
  revoke(id) {
    this.db.prepare('UPDATE credentials SET revoked=1 WHERE id=?').run(id);
    this.db.prepare('DELETE FROM sessions WHERE credential_id=?').run(id);
  }
  limit(key, max, windowMs = 60000) {
    const now = this.now();
    const row = this.db.prepare(`INSERT INTO limits VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET
      count=CASE WHEN expires<=? THEN 1 ELSE count+1 END,
      expires=CASE WHEN expires<=? THEN excluded.expires ELSE expires END RETURNING count`).get(key, now + windowMs, now, now);
    return row.count <= max;
  }
  prune() {
    for (const table of ['invites', 'challenges', 'sessions', 'limits']) this.db.prepare(`DELETE FROM ${table} WHERE expires<=?`).run(this.now());
  }
  list() { return this.db.prepare('SELECT id,label,revoked FROM credentials').all(); }
  close() { this.db.close(); }
}
