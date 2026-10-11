import { DatabaseSync } from 'node:sqlite';
import { ACCOUNT, XID, UUID, SHA, NAME, CONVERSATION, exact, canonical, sha, validDeclarations, ProductionAccessError } from './contracts.mjs';

const failure = () => new ProductionAccessError(503, 'access_store_rejected');
const integer = value => Number.isSafeInteger(value) && value >= 0;
const quoted = name => '"' + name.replaceAll('"', '""') + '"';
const tableNames = ['accounts', 'events', 'invitations', 'meta'];

function schemaShape(db) {
  const master = db.prepare('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name').all();
  if (master.length > 32) throw failure();
  const tables = master.filter(row => row.type === 'table').map(row => row.name).sort();
  if (canonical(tables) !== canonical(tableNames)) throw failure();
  return {
    master,
    tables: tables.map(name => ({
      name,
      columns: db.prepare(`PRAGMA table_xinfo(${quoted(name)})`).all(),
      foreignKeys: db.prepare(`PRAGMA foreign_key_list(${quoted(name)})`).all(),
      indexes: db.prepare(`PRAGMA index_list(${quoted(name)})`).all().map(index => ({
        ...index,
        columns: db.prepare(`PRAGMA index_xinfo(${quoted(index.name)})`).all(),
      })),
    })),
  };
}

/** Validate trusted-schema equivalence and every bounded durable record before
 * an existing store can be adopted. Does not migrate, repair or mutate that DB.
 * A missing v2 event is allowed only for an already-terminal status-readback
 * barrier; it never relaxes a pending/approved event or receipt link.
 */
export function validateExistingProductionStore(db, { schema, configuration, bindingSha }) {
  let expected;
  try {
    if (!(db instanceof DatabaseSync) || typeof schema !== 'string' || schema.length < 1 || schema.length > 32768
      || typeof bindingSha !== 'string' || !SHA.test(bindingSha)) throw failure();
    exact(configuration, Object.keys(configuration));
    if (!NAME.test(configuration.deploymentId) || !CONVERSATION.test(configuration.conversationId)
      || typeof configuration.consentVersion !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/u.test(configuration.consentVersion)) throw failure();
    expected = new DatabaseSync(':memory:');
    expected.exec(schema);
    if (canonical(schemaShape(db)) !== canonical(schemaShape(expected))) throw failure();
    if (db.prepare('PRAGMA quick_check').get().quick_check !== 'ok' || db.prepare('PRAGMA foreign_key_check').all().length) throw failure();

    const metaRows = db.prepare('SELECT * FROM meta LIMIT 2').all();
    const accounts = db.prepare('SELECT * FROM accounts LIMIT 21').all();
    const events = db.prepare('SELECT * FROM events LIMIT 41').all();
    const invitations = db.prepare('SELECT * FROM invitations LIMIT 1025').all();
    if (metaRows.length > 1 || accounts.length > 20 || events.length > 40 || invitations.length > 1024) throw failure();
    const meta = metaRows[0];
    if (!meta) {
      if (accounts.length || events.length || invitations.length) throw failure();
      return Object.freeze({ fresh: true, accounts: 0, events: 0, invitations: 0 });
    }
    if (meta.singleton !== 1 || meta.schema_version !== 1 || meta.binding_sha !== bindingSha
      || !integer(meta.last_ms) || meta.faulted !== 0 || !UUID.test(meta.boot_id)) throw failure();

    const byAccount = new Map(), byEvent = new Map(), seenReceipts = new Set(), seenXids = new Set(), seenReferences = new Set();
    for (const row of accounts) {
      if (typeof row.account_id !== 'string' || !ACCOUNT.test(row.account_id) || typeof row.xid !== 'string' || !XID.test(row.xid)
        || !UUID.test(row.receipt_id) || typeof row.receipt_json !== 'string' || Buffer.byteLength(row.receipt_json) > 8192
        || row.registration_id !== null && !UUID.test(row.registration_id)
        || byAccount.has(row.account_id) || seenXids.has(row.xid) || seenReceipts.has(row.receipt_id)
        || row.registration_id !== null && seenReferences.has(row.registration_id)) throw failure();
      const receipt = JSON.parse(row.receipt_json);
      exact(receipt, ['receiptId', 'accountId', 'consentVersion', 'adultSelfAttested', 'eligibilitySelfAttested', 'registrationConsent', 'issuedAt', 'expiresAt']);
      validDeclarations({ consentVersion: receipt.consentVersion, adultSelfAttested: receipt.adultSelfAttested,
        eligibilitySelfAttested: receipt.eligibilitySelfAttested, registrationConsent: receipt.registrationConsent }, configuration.consentVersion);
      if (canonical(receipt) !== row.receipt_json || receipt.receiptId !== row.receipt_id || receipt.accountId !== row.account_id
        || !integer(receipt.issuedAt) || !integer(receipt.expiresAt) || receipt.expiresAt <= receipt.issuedAt
        || receipt.expiresAt - receipt.issuedAt > 60 || receipt.issuedAt > Math.floor(meta.last_ms / 1000)) throw failure();
      const pending = row.state === 'pending';
      const validPending = pending && (row.event_version === 0 && row.provider_state === 'none' && row.event_id === null
        || row.event_version === 1 && row.provider_state === 'pending_allow' && UUID.test(row.event_id) && row.registration_id !== null);
      const validApproved = row.state === 'approved' && row.event_version === 1 && row.provider_state === 'approved'
        && UUID.test(row.event_id) && row.registration_id !== null;
      const validRevoked = row.state === 'revoked' && row.event_version === 2 && ['pending_remove', 'removed'].includes(row.provider_state)
        && UUID.test(row.event_id) && row.registration_id !== null;
      if (!validPending && !validApproved && !validRevoked) throw failure();
      byAccount.set(row.account_id, { ...row, receipt });
      seenXids.add(row.xid); seenReceipts.add(row.receipt_id); if (row.registration_id !== null) seenReferences.add(row.registration_id);
    }

    const seenVersions = new Set();
    for (const row of events) {
      if (!UUID.test(row.event_id) || !ACCOUNT.test(row.account_id) || ![1, 2].includes(row.version)
        || row.state !== (row.version === 1 ? 'approved' : 'revoked') || ![0, 1].includes(row.applied)
        || !SHA.test(row.digest) || typeof row.body !== 'string' || Buffer.byteLength(row.body) > 8192
        || byEvent.has(row.event_id) || seenVersions.has(row.account_id + ':' + row.version)) throw failure();
      const event = JSON.parse(row.body);
      exact(event, ['schemaVersion', 'eventId', 'deploymentId', 'conversationId', 'registrationId', 'accountId', 'version', 'state', 'occurredAt']);
      const account = byAccount.get(row.account_id);
      if (!account || canonical(event) !== row.body || sha(row.body) !== row.digest || event.schemaVersion !== 1
        || event.deploymentId !== configuration.deploymentId || event.conversationId !== configuration.conversationId
        || event.eventId !== row.event_id || event.accountId !== row.account_id || event.registrationId !== account.registration_id
        || event.version !== row.version || event.state !== row.state || !integer(event.occurredAt)
        // A delayed original registration can commit while an explicit retry
        // has reserved a newer receipt. The bound event can predate that retry.
        || event.occurredAt > Math.floor(meta.last_ms / 1000) + 30
        || row.version > account.event_version) throw failure();
      if (row.version === 2 && (account.state !== 'revoked' || account.event_id !== row.event_id
        || row.applied === 1 && account.provider_state !== 'removed')) throw failure();
      byEvent.set(row.event_id, row); seenVersions.add(row.account_id + ':' + row.version);
    }
    for (const account of byAccount.values()) {
      const event = byEvent.get(account.event_id);
      if (account.event_version === 0) {
        if (seenVersions.has(account.account_id + ':1') || seenVersions.has(account.account_id + ':2')) throw failure();
      } else if (account.state === 'revoked') {
        if (event && (event.account_id !== account.account_id || event.version !== 2 || event.state !== 'revoked')) throw failure();
        // A signed current WP status may have established a durable deny barrier
        // before its immutable event arrives. Absence does not grant access.
      } else if (!event || event.account_id !== account.account_id || event.version !== 1
        || event.state !== 'approved' || event.applied !== (account.state === 'approved' ? 1 : 0)) throw failure();
    }

    const liveInvitationAccounts = new Set();
    for (const invitation of invitations) {
      const account = byAccount.get(invitation.account_id);
      if (!SHA.test(invitation.token_hash) || !account || !integer(invitation.expires_ms)
        || invitation.expires_ms > meta.last_ms + 600_000 || ![0, 1].includes(invitation.used)) throw failure();
      if (invitation.used === 0) {
        if (account.state !== 'approved' || account.provider_state !== 'approved' || liveInvitationAccounts.has(account.account_id)) throw failure();
        liveInvitationAccounts.add(account.account_id);
      }
    }
    return Object.freeze({ fresh: false, accounts: accounts.length, events: events.length, invitations: invitations.length });
  } catch { throw failure(); }
  finally { try { expected?.close(); } catch {} }
}
