import { createHash } from 'node:crypto';

export const ROUND = 'synthetic_round_local';
export const SUBJECT = /^synthetic_[a-z][a-z0-9_]{0,39}$/u;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
export function validEvent(event) {
  const keys = ['schema_version', 'event_id', 'subject', 'round_id', 'version', 'state', 'occurred_at'];
  return event && typeof event === 'object' && !Array.isArray(event) &&
    Object.keys(event).length === keys.length && keys.every((key) => Object.hasOwn(event, key)) &&
    event.schema_version === 1 && typeof event.event_id === 'string' && UUID.test(event.event_id) &&
    typeof event.subject === 'string' && SUBJECT.test(event.subject) && event.round_id === ROUND &&
    Number.isSafeInteger(event.version) && event.version > 0 && ['approved', 'revoked'].includes(event.state) &&
    typeof event.occurred_at === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/u.test(event.occurred_at) &&
    Number.isFinite(Date.parse(event.occurred_at)) && new Date(event.occurred_at).toISOString() === event.occurred_at.replace('Z', '.000Z');
}

/** One process shares the API serialization queue and database. An accepted but
 * unapplied event denies participation across crashes; identical retry reconciles
 * the existing provider idempotency operation. This is not a distributed lock. */
export function createWordPressEventGate({ db, apply, HttpError, requireApproval = false }) {
  db.exec(`CREATE TABLE IF NOT EXISTS wordpress_events (
    event_id TEXT PRIMARY KEY, subject TEXT NOT NULL REFERENCES fixtures(id),
    version INTEGER NOT NULL, state TEXT NOT NULL, digest TEXT NOT NULL,
    applied INTEGER NOT NULL DEFAULT 0, UNIQUE(subject,version));`);
  const latest = (subject) => db.prepare('SELECT * FROM wordpress_events WHERE subject=? ORDER BY version DESC LIMIT 1').get(subject);
  const fail = (status, message) => { throw new HttpError(status, message); };
  return {
    assertCurrent(subject) {
      const event = latest(subject);
      if ((!event && requireApproval) || event && (event.state !== 'approved' || event.applied !== 1)) fail(403, 'Current WordPress approval required.');
    },
    assertNotRevoked(subject) {
      if (latest(subject)?.state === 'revoked') fail(409, 'WordPress revocation is terminal in this proof.');
    },
    async ingest(event) {
      if (!validEvent(event)) fail(400, 'Invalid synthetic WordPress event.');
      if (!db.prepare('SELECT id FROM fixtures WHERE id=?').get(event.subject)) fail(409, 'Pre-provisioned synthetic fixture required.');
      const canonical = JSON.stringify(['schema_version', 'event_id', 'subject', 'round_id', 'version', 'state', 'occurred_at'].map((key) => event[key]));
      const digest = createHash('sha256').update(canonical).digest('hex');
      const duplicate = db.prepare('SELECT * FROM wordpress_events WHERE event_id=? OR (subject=? AND version=?)')
        .all(event.event_id, event.subject, event.version);
      if (duplicate.some((row) => row.digest !== digest)) fail(409, 'Conflicting event identity or version.');
      const previous = latest(event.subject);
      const ack = { ok: true, event_id: event.event_id, version: event.version };
      if (previous && event.version < previous.version) return { ...ack, outcome: 'STALE_NO_OP' };
      if (previous?.state === 'revoked' && event.state === 'approved') fail(409, 'WordPress revocation is terminal in this proof.');
      if (previous?.state === 'revoked' && event.version > previous.version) {
        if (previous.applied !== 1) fail(409, 'Retry the original pending revocation.');
        return { ...ack, outcome: 'TERMINAL_NO_OP' };
      }
      if (duplicate[0]?.applied === 1) return { ...ack, outcome: 'IDEMPOTENT_NO_OP' };
      if (!duplicate.length) {
        // Never let ordinary journal capacity prevent a terminal deny operation.
        // At most 20 subjects can add one reserved revocation each (220 total).
        if (event.state !== 'revoked' && db.prepare('SELECT count(*) AS n FROM wordpress_events').get().n >= 200) fail(409, 'Synthetic journal capacity reached.');
        if (!previous && db.prepare('SELECT count(DISTINCT subject) AS n FROM wordpress_events').get().n >= 20) fail(409, 'Synthetic round capacity reached.');
        db.prepare('INSERT INTO wordpress_events(event_id,subject,version,state,digest) VALUES(?,?,?,?,?)')
          .run(event.event_id, event.subject, event.version, event.state, digest);
      }
      // The durable pending row above is already a fail-closed access barrier.
      await apply(event);
      db.prepare('UPDATE wordpress_events SET applied=1 WHERE event_id=?').run(event.event_id);
      return { ...ack, outcome: 'APPLIED' };
    },
  };
}
