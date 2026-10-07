/** Exact synthetic three-store recovery contract. No I/O, no live authority. */
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { validEvent } from '../local-access/wordpress-events.mjs';

export const STORES = Object.freeze(['wordpress-mysql', 'access-sqlite', 'polis-postgresql']);
export const MODE = 'coordinated-synthetic-restore-only';
export const sha256 = (value) => createHash('sha256').update(value).digest('hex');
export const canonical = (value) => JSON.stringify(value);
const check = (condition) => { if (!condition) throw new Error('Coordinated synthetic recovery boundary failed.'); };
const HEX = /^[a-f0-9]{64}$/u;

export function binding(run, store, scopeHash) {
  check(/^[a-f0-9]{24}$/u.test(run) && STORES.includes(store) && HEX.test(scopeHash));
  return { version: 1, algorithm: 'AES-256-GCM', run, store, scopeHash };
}

export function seal(plaintext, key, header) {
  check(Buffer.isBuffer(plaintext) && Buffer.isBuffer(key) && key.length === 32);
  check(canonical(header) === canonical(binding(header.run, header.store, header.scopeHash)));
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(canonical(header)));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.from(canonical({ header, nonce: nonce.toString('hex'), tag: cipher.getAuthTag().toString('hex'), ciphertext: ciphertext.toString('base64') }));
}

export function unseal(encoded, key, expectedHeader) {
  try {
    check(Buffer.isBuffer(key) && key.length === 32);
    const envelope = JSON.parse(encoded.toString('utf8'));
    check(Object.keys(envelope).sort().join(',') === 'ciphertext,header,nonce,tag');
    check(canonical(envelope.header) === canonical(expectedHeader));
    check(canonical(expectedHeader) === canonical(binding(expectedHeader.run, expectedHeader.store, expectedHeader.scopeHash)));
    check(/^[a-f0-9]{24}$/u.test(envelope.nonce) && /^[a-f0-9]{32}$/u.test(envelope.tag));
    check(typeof envelope.ciphertext === 'string' && /^[A-Za-z0-9+/]*={0,2}$/u.test(envelope.ciphertext));
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.nonce, 'hex'), { authTagLength: 16 });
    decipher.setAAD(Buffer.from(canonical(expectedHeader)));
    decipher.setAuthTag(Buffer.from(envelope.tag, 'hex'));
    return Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]);
  } catch { throw new Error('Encrypted recovery component authentication failed.'); }
}

export function signManifest(manifest, key) {
  return { manifest, mac: createHmac('sha256', key).update('FNCP-COORDINATED-MANIFEST-v1\n' + canonical(manifest)).digest('hex') };
}

export function verifyManifest(signed, key, expectedRun, expectedScopeHash, components) {
  try {
    const { manifest, mac } = signed;
    check(Object.keys(signed).sort().join(',') === 'mac,manifest' && HEX.test(mac));
    const expected = signManifest(manifest, key).mac;
    check(timingSafeEqual(Buffer.from(mac, 'hex'), Buffer.from(expected, 'hex')));
    check(manifest.version === 1 && manifest.mode === MODE && manifest.run === expectedRun && manifest.scopeHash === expectedScopeHash);
    check(canonical(Object.keys(manifest.components).sort()) === canonical([...STORES].sort()));
    check(canonical(Object.keys(components).sort()) === canonical([...STORES].sort()));
    for (const store of STORES) {
      const item = manifest.components[store];
      check(item.filename === store + '.aesgcm' && item.bytes === components[store].length && item.sha256 === sha256(components[store]));
      check(item.mode === '600');
    }
    return manifest;
  } catch { throw new Error('Exact recovery manifest authentication or component set failed.'); }
}

export function eventDigest(event) {
  return sha256(canonical(['schema_version', 'event_id', 'subject', 'round_id', 'version', 'state', 'occurred_at'].map(key => event[key])));
}

/** Metadata is held in memory only. Return only aggregates, never subject/XID/event IDs. */
export function validateConsistency(journal, access, operations) {
  check(journal?.schema_version === 1 && journal.subjects && journal.events);
  const records = Object.values(journal.events); const subjects = Object.entries(journal.subjects);
  check(subjects.length === 3 && records.length === 6 && access.fixtures.length === 3 && access.approvals.length === 3);
  check(access.rounds.length === 1 && access.rounds[0].open === 0 && access.sessions.length === 0 && access.events.length === 6);
  check(access.invitations.every(row => row.used === 1 && row.round === access.rounds[0].id && access.fixtures.some(f => f.id === row.fixture)));
  check(new Set(access.fixtures.map(row => row.id)).size === 3 && access.fixtures.every(row => /^synthetic_[a-z][a-z0-9_]{0,39}$/u.test(row.id)));
  check(operations.length >= 3 && operations.length <= 100 && new Set(operations.map(row => row.xid)).size === operations.length);
  check(operations.every(row => /^fncp_[A-Za-z0-9_-]{16,251}$/u.test(row.xid) && row.operation_version === 2 && row.desired_present === false));
  for (const [id, record] of Object.entries(journal.events)) {
    check(validEvent(record.event) && id === record.event.event_id && record.delivered === true && record.last_result === 'ACKNOWLEDGED');
    check(record.body === canonical(record.event));
    const row = access.events.find(item => item.event_id === id);
    check(row && row.subject === record.event.subject && row.version === record.event.version && row.state === record.event.state && row.applied === 1 && row.digest === eventDigest(record.event));
  }
  for (const [key, subject] of subjects) {
    const latest = journal.events[subject.event_id]?.event;
    check(latest && key === latest.round_id + ':' + latest.subject && subject.version === 2 && subject.state === 'revoked' && latest.state === 'revoked' && latest.version === 2);
    const history = records.filter(record => record.event.subject === latest.subject).map(record => record.event).sort((a,b) => a.version-b.version);
    check(history.length === 2 && history[0].version === 1 && history[0].state === 'approved' && history[1].version === 2 && history[1].state === 'revoked');
    const approval = access.approvals.find(row => row.fixture === latest.subject);
    check(access.fixtures.some(row => row.id === latest.subject) && approval?.state === 'revoked' && approval.round === access.rounds[0].id);
    check(operations.some(row => row.xid === approval.xid && row.operation_version === 2 && row.desired_present === false));
  }
  return { fixtures: 3, revoked: 3, wordpressEvents: 6, appliedEvents: 6, terminalVersions: 3,
    pendingEvents: 0, activeSessions: 0, unusedInvitations: 0, providerTombstones: operations.length, crossStoreConsistent: true };
}
