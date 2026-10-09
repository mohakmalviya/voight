import { DatabaseSync } from 'node:sqlite';
import { createHash, createHmac, randomBytes } from 'node:crypto';

export const token = () => randomBytes(32).toString('base64url');
export const digest = value => createHash('sha256').update(value).digest('hex');

function atomic(db, action) {
  db.exec('BEGIN IMMEDIATE');
  try { const result = action(); db.exec('COMMIT'); return result; }
  catch (error) { db.exec('ROLLBACK'); throw error; }
}

const retry = (expires, now) => Math.max(1, Math.ceil((expires - now) / 1000));

// Invited credentials and anonymous public subjects keep separate accounting tables.
// Credential rows reference real credentials and observe revocation; public rows do not.
const SCOPES = {
  credential: { resources: 'resource_usage', bytes: 'byte_usage', subject: 'credential_id' },
  public: { resources: 'public_resource_usage', bytes: 'public_byte_usage', subject: 'subject' },
};

export class Store {
  constructor(path, now = Date.now) {
    this.now = now;
    this.db = new DatabaseSync(path, { timeout: 5000 });
    // Statements are compiled once and reused: compiling them on every call was most of the gateway's CPU under load.
    this.statements = new Map();
    // synchronous=NORMAL: with WAL, commits stop waiting for the disk. A power cut can lose the last moments of counters,
    // never corrupt the database.
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS invites (hash TEXT PRIMARY KEY, label TEXT NOT NULL, expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS credentials (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, label TEXT NOT NULL, key TEXT NOT NULL, counter INTEGER NOT NULL, transports TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS challenges (hash TEXT PRIMARY KEY, payload TEXT NOT NULL, expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS sessions (hash TEXT PRIMARY KEY, credential_id TEXT NOT NULL REFERENCES credentials(id), ua TEXT NOT NULL, expires INTEGER NOT NULL, requests INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS limits (key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS session_expiry ON sessions(expires);
      CREATE TABLE IF NOT EXISTS session_signals (session_hash TEXT PRIMARY KEY REFERENCES sessions(hash) ON DELETE CASCADE, webdriver INTEGER NOT NULL CHECK(webdriver IN (0,1)));
      CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS resource_usage (credential_id TEXT NOT NULL REFERENCES credentials(id), hash TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(credential_id,hash));
      CREATE TABLE IF NOT EXISTS byte_usage (credential_id TEXT NOT NULL REFERENCES credentials(id), bucket INTEGER NOT NULL, bytes INTEGER NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(credential_id,bucket));
      CREATE INDEX IF NOT EXISTS resource_expiry ON resource_usage(expires);
      CREATE INDEX IF NOT EXISTS byte_expiry ON byte_usage(expires);
      CREATE TABLE IF NOT EXISTS public_resource_usage (subject TEXT NOT NULL, hash TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(subject,hash));
      CREATE TABLE IF NOT EXISTS public_byte_usage (subject TEXT NOT NULL, bucket INTEGER NOT NULL, bytes INTEGER NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(subject,bucket));
      CREATE INDEX IF NOT EXISTS public_resource_expiry ON public_resource_usage(expires);
      CREATE INDEX IF NOT EXISTS public_byte_expiry ON public_byte_usage(expires);
      CREATE TABLE IF NOT EXISTS clearances (hash TEXT PRIMARY KEY, network TEXT NOT NULL, expires INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS clearance_network ON clearances(network, expires);
      CREATE TABLE IF NOT EXISTS bans (network TEXT PRIMARY KEY, until INTEGER NOT NULL, count INTEGER NOT NULL, forget INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS human_passes (hash TEXT PRIMARY KEY, ua TEXT NOT NULL, expires INTEGER NOT NULL);`);
    this.stmt('INSERT OR IGNORE INTO settings VALUES(?,?)').run('resource_hash_key', token());
    this.resourceKey = Buffer.from(this.stmt('SELECT value FROM settings WHERE key=?').get('resource_hash_key').value, 'base64url');
  }
  stmt(sql) {
    let statement = this.statements.get(sql);
    if (!statement) this.statements.set(sql, statement = this.db.prepare(sql));
    return statement;
  }
  invite(label, seconds = 3600) {
    const value = token();
    this.stmt('INSERT INTO invites VALUES(?,?,?)').run(digest(value), label, this.now() + seconds * 1000);
    return value;
  }
  getInvite(value) { return this.stmt('SELECT * FROM invites WHERE hash=? AND expires>?').get(digest(value), this.now()); }
  challenge(payload) {
    const value = token();
    this.stmt('INSERT INTO challenges VALUES(?,?,?)').run(digest(value), JSON.stringify(payload), this.now() + 120000);
    return value;
  }
  // The human check page's trip to the hop page and back, under an id the page made up. Read it with
  // peekChallenge/takeChallenge(`hop:${id}`); ceremony cookies never contain a colon, so the two cannot meet.
  hop(id, payload) {
    return this.stmt('INSERT OR IGNORE INTO challenges VALUES(?,?,?)').run(digest(`hop:${id}`), JSON.stringify(payload), this.now() + 60000).changes === 1;
  }
  peekChallenge(value) {
    const row = this.stmt('SELECT payload FROM challenges WHERE hash=? AND expires>?').get(digest(value ?? ''), this.now());
    return row ? JSON.parse(row.payload) : null;
  }
  takeChallenge(value) {
    const row = this.stmt('DELETE FROM challenges WHERE hash=? RETURNING *').get(digest(value));
    return row && row.expires > this.now() ? JSON.parse(row.payload) : null;
  }
  enroll(inviteHash, userID, credential) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.stmt('DELETE FROM invites WHERE hash=? AND expires>? RETURNING label').get(inviteHash, this.now());
      if (!row) throw new Error('Invitation expired or already used');
      this.stmt('INSERT INTO credentials(id,user_id,label,key,counter,transports) VALUES(?,?,?,?,?,?)').run(
        credential.id, userID, row.label, Buffer.from(credential.publicKey).toString('base64url'), credential.counter, JSON.stringify(credential.transports ?? []));
      this.db.exec('COMMIT');
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  credential(id) {
    const row = this.stmt('SELECT * FROM credentials WHERE id=? AND revoked=0').get(id);
    return row ? { ...row, publicKey: new Uint8Array(Buffer.from(row.key, 'base64url')), transports: JSON.parse(row.transports) } : null;
  }
  updateCounter(id, before, after) {
    return this.stmt('UPDATE credentials SET counter=? WHERE id=? AND counter=? AND revoked=0').run(after, id, before).changes === 1;
  }
  session(credentialID, ua, seconds, webdriver = null) {
    const value = token();
    return atomic(this.db, () => {
      this.stmt('INSERT INTO sessions(hash,credential_id,ua,expires) VALUES(?,?,?,?)').run(digest(value), credentialID, digest(ua), this.now() + seconds * 1000);
      if (typeof webdriver === 'boolean') this.stmt('INSERT INTO session_signals VALUES(?,?)').run(digest(value), Number(webdriver));
      return value;
    });
  }
  admit(value, ua, maxRequests) {
    // One atomic increment prevents concurrent requests exceeding the budget.
    const row = this.stmt(`UPDATE sessions SET requests=requests+1 WHERE hash=? AND ua=? AND expires>? AND requests<?
      AND EXISTS(SELECT 1 FROM credentials WHERE id=sessions.credential_id AND revoked=0) RETURNING credential_id`).get(digest(value), digest(ua), this.now(), maxRequests);
    if (!row) return row;
    const signal = this.stmt('SELECT webdriver FROM session_signals WHERE session_hash=?').get(digest(value));
    return { ...row, webdriver: signal ? Boolean(signal.webdriver) : null };
  }
  logout(value) { this.stmt('DELETE FROM sessions WHERE hash=?').run(digest(value)); }
  revoke(id) {
    this.stmt('UPDATE credentials SET revoked=1 WHERE id=?').run(id);
    this.stmt('DELETE FROM sessions WHERE credential_id=?').run(id);
  }
  limit(key, max, windowMs = 60000) {
    const now = this.now();
    const row = this.stmt(`INSERT INTO limits VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET
      count=CASE WHEN expires<=? THEN 1 ELSE count+1 END,
      expires=CASE WHEN expires<=? THEN excluded.expires ELSE expires END RETURNING count`).get(key, now + windowMs, now, now);
    return row.count <= max;
  }
  // A flag that lasts for a while, kept in the limits table so it is pruned with it.
  mark(key, ms) { this.stmt('INSERT INTO limits VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=1, expires=excluded.expires').run(key, this.now() + ms); }
  marked(key) { return Boolean(this.stmt('SELECT 1 FROM limits WHERE key=? AND expires>?').get(key, this.now())); }
  resetLimit(key) { this.stmt('DELETE FROM limits WHERE key=?').run(key); }
  // A resource is the normalized path plus query. Never persist either in plaintext.
  beginResource(subject, resource, config, scope = 'credential') {
    const t = SCOPES[scope];
    return atomic(this.db, () => {
      const now = this.now();
      const bytes = this.stmt(`SELECT COALESCE(SUM(bytes),0) AS total, MIN(expires) AS expires FROM ${t.bytes} WHERE ${t.subject}=? AND expires>?`).get(subject, now);
      if (bytes.total >= config.bytesPerWindow) return { reason: 'byte_budget', retryAfter: retry(bytes.expires, now) };
      const hash = createHmac('sha256', this.resourceKey).update(resource).digest('hex');
      const existing = this.stmt(`SELECT 1 FROM ${t.resources} WHERE ${t.subject}=? AND hash=? AND expires>?`).get(subject, hash, now);
      if (!existing) {
        const resources = this.stmt(`SELECT COUNT(*) AS total, MIN(expires) AS expires FROM ${t.resources} WHERE ${t.subject}=? AND expires>?`).get(subject, now);
        if (resources.total >= config.resourcesPerWindow) return { reason: 'resource_budget', retryAfter: retry(resources.expires, now) };
      }
      this.stmt(`INSERT INTO ${t.resources} VALUES(?,?,?) ON CONFLICT(${t.subject},hash) DO UPDATE SET expires=MAX(expires,excluded.expires)`)
        .run(subject, hash, now + config.extractionWindowSeconds * 1000);
      return null;
    });
  }
  chargeBytes(subject, size, config, scope = 'credential') {
    if (!Number.isSafeInteger(size) || size < 0) throw new Error('Invalid byte charge');
    const t = SCOPES[scope];
    return atomic(this.db, () => {
      const now = this.now();
      if (scope === 'credential' && !this.stmt('SELECT 1 FROM credentials WHERE id=? AND revoked=0').get(subject)) return { reason: 'credential_revoked', status: 403 };
      const used = this.stmt(`SELECT COALESCE(SUM(bytes),0) AS total, MIN(expires) AS expires FROM ${t.bytes} WHERE ${t.subject}=? AND expires>?`).get(subject, now);
      if (used.total + size > config.bytesPerWindow) return { reason: 'byte_budget', retryAfter: retry(used.expires ?? now + config.extractionWindowSeconds * 1000, now) };
      // Round expiry UP to the end of this second: never undercount the rolling window.
      const bucket = Math.floor(now / 1000) * 1000;
      this.stmt(`INSERT INTO ${t.bytes} VALUES(?,?,?,?) ON CONFLICT(${t.subject},bucket) DO UPDATE SET bytes=bytes+excluded.bytes, expires=MAX(expires,excluded.expires)`)
        .run(subject, bucket, size, bucket + 1000 + config.extractionWindowSeconds * 1000);
      return null;
    });
  }
  // Networks are stored as keyed hashes. The raw address never reaches the database.
  pseudonym(network) { return createHmac('sha256', this.resourceKey).update(`network:${network}`).digest('hex').slice(0, 32); }
  clearanceCount(network) {
    return this.stmt('SELECT COUNT(*) AS n FROM clearances WHERE network=? AND expires>?').get(network, this.now()).n;
  }
  // The count is rechecked inside the transaction so parallel solutions cannot exceed the cap.
  clear(network, max, seconds) {
    return atomic(this.db, () => {
      if (this.clearanceCount(network) >= max) return null;
      const value = token();
      this.stmt('INSERT INTO clearances VALUES(?,?,?)').run(digest(value), network, this.now() + seconds * 1000);
      return value;
    });
  }
  clearance(value) {
    return value ? this.stmt('SELECT hash, network FROM clearances WHERE hash=? AND expires>?').get(digest(value), this.now()) : undefined;
  }
  banned(network) { return this.stmt('SELECT until, count FROM bans WHERE network=? AND until>?').get(network, this.now()); }
  // A repeat within the memory period lasts four times longer, capped at maxSeconds.
  ban(network, baseSeconds, maxSeconds) {
    return atomic(this.db, () => {
      const now = this.now();
      const previous = this.stmt('SELECT count FROM bans WHERE network=? AND forget>?').get(network, now);
      const count = (previous?.count ?? 0) + 1;
      const seconds = Math.min(maxSeconds, baseSeconds * 4 ** (count - 1));
      const until = now + seconds * 1000;
      this.stmt('INSERT INTO bans VALUES(?,?,?,?) ON CONFLICT(network) DO UPDATE SET until=excluded.until, count=excluded.count, forget=excluded.forget')
        .run(network, until, count, until + maxSeconds * 1000);
      return seconds;
    });
  }
  // Lifting a block also clears the counters that led to it, so the visitor gets in immediately.
  unban(network) {
    return atomic(this.db, () => {
      for (const key of [`strike:${network}`, `all:${network}`, `reader:network:${network}`]) this.resetLimit(key);
      return this.stmt('DELETE FROM bans WHERE network=?').run(network).changes > 0;
    });
  }
  // A human pass is bound to the browser's user agent, so a copied cookie does not work in another client as is.
  pass(ua, seconds) {
    const value = token();
    this.stmt('INSERT INTO human_passes VALUES(?,?,?)').run(digest(value), digest(ua), this.now() + seconds * 1000);
    return value;
  }
  human(value, ua) {
    return value ? this.stmt('SELECT hash FROM human_passes WHERE hash=? AND ua=? AND expires>?').get(digest(value), digest(ua), this.now()) : undefined;
  }
  revokePass(hash) { this.stmt('DELETE FROM human_passes WHERE hash=?').run(hash); }
  bans() {
    return this.stmt('SELECT network, until, count FROM bans WHERE until>? ORDER BY until DESC').all(this.now())
      .map(row => ({ network: row.network, until: new Date(row.until).toISOString(), count: row.count }));
  }
  usage() {
    const now = this.now();
    return this.stmt(`SELECT id,label,revoked,
      (SELECT COALESCE(SUM(bytes),0) FROM byte_usage WHERE credential_id=credentials.id AND expires>?) AS bytes,
      (SELECT COUNT(*) FROM resource_usage WHERE credential_id=credentials.id AND expires>?) AS resources
      FROM credentials`).all(now, now);
  }
  prune() {
    for (const table of ['invites', 'challenges', 'sessions', 'limits', 'resource_usage', 'byte_usage', 'public_resource_usage', 'public_byte_usage', 'clearances', 'human_passes']) {
      this.stmt(`DELETE FROM ${table} WHERE expires<=?`).run(this.now());
    }
    // Ban rows outlive the ban itself so a quick repeat offence escalates.
    this.stmt('DELETE FROM bans WHERE forget<=?').run(this.now());
  }
  list() { return this.stmt('SELECT id,label,revoked FROM credentials').all(); }
  close() { this.db.close(); }
}
