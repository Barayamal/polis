/** Fresh-only bootstrap sequencing, not a runnable Pol.is/Docker adapter.
 * The injected driver is trusted code; reported ownership/image/network facts
 * are NOT independently verified by this module. No default network/SQL driver,
 * image approval, process launch, activation, adoption or replay is provided.
 * Requests, response bodies, privateDirectory and returned binding stay private.
 */
import { mkdtemp, realpath, chmod, lstat, open, readdir } from 'node:fs/promises';
import { constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { isProxy } from 'node:util/types';
import { validateFreshBootstrapResult } from '../fresh-bootstrap-result.mjs';

const SEED_URL = new URL('../seed-statements.json', import.meta.url);
const SEED_SHA = 'b8c49ddaab72740df997b4975e84b0a51501fa97e1c622420826f4840bc6e06b';
const DEDICATED = 'sha256:07f8a21105ed90963ccdf0981d884323116187583a464bb581db14c621d33a98';
const ID = /^[a-f0-9]{64}$/u;
const active = new WeakMap();
const fail = () => new Error('Fresh bootstrap protocol failed; private evidence preserved and replay denied.');
const sha = value => createHash('sha256').update(value).digest('hex');
const freeze = value => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; };
function exact(value, names) {
  if (!value || typeof value !== 'object' || isProxy(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value)) || Reflect.ownKeys(value).length !== names.length) throw fail();
  const fields = Object.getOwnPropertyDescriptors(value);
  if (names.some(name => !fields[name] || !Object.hasOwn(fields[name], 'value'))) throw fail();
  return Object.fromEntries(names.map(name => [name, fields[name].value]));
}
const stamp = info => ({ dev: info.dev, ino: info.ino, uid: info.uid, mode: info.mode, size: info.size });
const same = (a, b) => ['dev', 'ino', 'uid', 'mode', 'size'].every(key => a[key] === b[key]);
const regular = info => info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && (info.mode & 0o777) === 0o600;
async function seeds() {
  const before = await lstat(SEED_URL);
  if (!before.isFile() || before.isSymbolicLink() || before.size > 16384) throw fail();
  const file = await open(SEED_URL, constants.O_RDONLY | constants.O_NOFOLLOW);
  let bytes;
  try { if (!same(await file.stat(), stamp(before))) throw fail(); bytes = await file.readFile(); }
  finally { await file.close(); }
  if (!same(await lstat(SEED_URL), stamp(before))) throw fail();
  if (sha(bytes) !== SEED_SHA) throw fail();
  const result = JSON.parse(bytes);
  if (!Array.isArray(result) || result.length !== 15 || new Set(result).size !== 15 || result.some(s => typeof s !== 'string' || !s.length || s.length > 1000)) throw fail();
  return Object.freeze(result);
}
async function write(state, name, value) {
  const bytes = JSON.stringify(value, null, 2) + '\n';
  const file = await open(join(state.directory, name), constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try { await file.writeFile(bytes); await file.sync(); const info = await file.stat(); if (!regular(info)) throw fail(); state.files.set(name, { ...stamp(info), sha: sha(bytes) }); }
  finally { await file.close(); }
}
async function integrity(state) {
  const info = await lstat(state.directory);
  if (!info.isDirectory() || info.isSymbolicLink() || ['dev', 'ino', 'uid', 'mode'].some(key => info[key] !== state.stamp[key]) ||
      (info.mode & 0o777) !== 0o700 || await realpath(state.directory) !== state.directory) throw fail();
  const names = await readdir(state.directory);
  if (names.length !== state.files.size || names.some(name => !state.files.has(name))) throw fail();
  for (const [name, expected] of state.files) {
    const path = join(state.directory, name); const before = await lstat(path);
    if (!regular(before) || !same(before, expected)) throw fail();
    const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { const info = await file.stat(); if (!regular(info) || !same(info, expected) || sha(await file.readFile()) !== expected.sha || !same(await lstat(path), expected)) throw fail(); }
    finally { await file.close(); }
  }
  await seeds();
}
async function record(state, event, facts = {}) {
  await integrity(state);
  const sequence = state.sequence + 1;
  await write(state, `ledger-${String(sequence).padStart(4, '0')}.json`, { event, ...facts });
  state.sequence = sequence;
}
/** This proves only active in-process protocol origin and integrity. A future
 * concrete driver must separately prove exact fresh resource ownership/pins. */
export async function verifyBootstrapProtocolRequest(request) {
  if (arguments.length !== 1 || !request || typeof request !== 'object' || isProxy(request)) throw fail();
  const entry = active.get(request);
  if (!entry || (entry.state.cancelled && !entry.cleanup)) throw fail();
  try {
    await integrity(entry.state);
    if (active.get(request) !== entry || (entry.state.cancelled && !entry.cleanup)) throw fail();
  } catch { throw fail(); }
}
/** Private in-process lineage/cancellation handoff, not transferable authority.
 * The HTTP adapter must still verify the active request before/after each I/O. */
export async function bootstrapHttpAuthority(request) {
  if (arguments.length !== 1) throw fail();
  await verifyBootstrapProtocolRequest(request);
  const entry = active.get(request);
  if (!entry || entry.cleanup || entry.state.cancelled) throw fail();
  return Object.freeze({ scope: entry.state.httpScope, signal: entry.state.aborter.signal });
}
/** Fixed upstream HTTP mapping for an active protocol callback. Does not send
 * anything, select an origin, attach a token or prove the HTTP hop used TLS.
 * The future concrete driver must separately bind an exact owned helper and
 * the same one-shot issuer token. No redirects or arbitrary routes are offered. */
export async function httpRequestForBootstrap(request) {
  if (arguments.length !== 1) throw fail();
  await verifyBootstrapProtocolRequest(request);
  const methods = { 'create-conversation': 'POST', 'create-seed': 'POST', 'read-seeds': 'GET',
    'close-conversation': 'PUT', 'read-conversation': 'GET' };
  const method = methods[request.operation]; if (!method) throw fail();
  let path = request.operation.includes('seed') ? '/api/v3/comments' : '/api/v3/conversations';
  let body = null;
  if (method === 'GET') {
    const query = new URLSearchParams({ conversation_id: request.payload.conversationId });
    if (request.operation === 'read-seeds') { query.set('moderation', 'true'); query.set('include_voting_patterns', 'true'); }
    path += '?' + query.toString();
  } else body = JSON.stringify(request.payload);
  return freeze({ method, path, headers: { accept: 'application/json', 'content-type': 'application/json',
    'x-forwarded-proto': 'https' }, body });
}
async function call(state, operation, payload, cleanup = false) {
  await integrity(state); if (state.cancelled && !cleanup) throw fail();
  const request = freeze({ operation, payload }); active.set(request, { state, cleanup });
  try {
    const result = await state.driver(request);
    await verifyBootstrapProtocolRequest(request);
    return result;
  } finally { active.delete(request); }
}
function response(value) {
  const result = exact(value, ['status', 'body']);
  if (result.status !== 200 || typeof result.body !== 'string' || Buffer.byteLength(result.body) > 65536) throw fail();
  const text = result.body.replace(/^[ \t\r\n]+|[ \t\r\n]+$/gu, ''); const body = JSON.parse(text);
  // Express JSON output is canonical here. Reject duplicate keys/ambiguous JSON.
  if (JSON.stringify(body) !== text) throw fail();
  return body;
}
const integer = value => Number.isSafeInteger(value) && value >= 0 && value <= 2147483647 && !Object.is(value, -0);
function conversation(value) {
  if (!value || Array.isArray(value) || typeof value !== 'object') throw fail();
  return validateFreshBootstrapResult({ conversationId: value.conversation_id, statementIds: Array.from({ length: 15 }, (_, i) => i) }).conversationId;
}
function helper(value) {
  const item = exact(value, ['id', 'imageId', 'os', 'architecture', 'ordinary', 'owned', 'loopbackOnly', 'egressVerified', 'schemaReady', 'running']);
  if (typeof item.id !== 'string' || !ID.test(item.id) || typeof item.imageId !== 'string' || !/^sha256:[a-f0-9]{64}$/u.test(item.imageId) || item.imageId === DEDICATED ||
      item.os !== 'linux' || item.architecture !== 'arm64' || ['ordinary', 'owned', 'loopbackOnly', 'egressVerified', 'schemaReady', 'running'].some(k => item[k] !== true)) throw fail();
  return Object.freeze({ id: item.id, imageId: item.imageId });
}
async function finishHelper(state) {
  if (state.closed || !state.inspectionAttempted) return;
  // The protocol has no resource to name after failed/late inspection. Its
  // owning runtime manager must use its own independent exact-ID ledger;
  // never dispatch identity-less cleanup or rediscover a helper by name.
  if (!state.helper) throw fail();
  // A failed read-only pre-stop check can retry; a dispatched stop cannot.
  if (!state.closeDispatched) {
    await record(state, 'HELPER_CLOSE_ATTEMPTED', { id: state.helper.id });
    state.closeDispatched = true;
    const closed = exact(await call(state, 'close-helper', { id: state.helper.id }, true), ['id', 'running']);
    if (!state.helper || closed.id !== state.helper.id || closed.running !== false) throw fail();
    state.closeAcknowledged = true;
  }
  if (!state.closeAcknowledged) throw fail();
  const checked = exact(await call(state, 'inspect-closed', { id: state.helper.id }, true), ['id', 'running']);
  if (checked.id !== state.helper.id || checked.running !== false) throw fail();
  await record(state, 'HELPER_CLOSED_INJECTED_READBACK', { id: state.helper.id }); state.closed = true;
}

/** Explicit trusted injection only. Factory writes new private evidence files;
 * no existing directory, arbitrary origin, credentials or resource is accepted. */
export async function createBootstrapProtocol(options) {
  if (arguments.length !== 1) throw fail();
  const { driver } = exact(options, ['driver']); if (typeof driver !== 'function' || isProxy(driver)) throw fail();
  let fixedSeeds;
  try { fixedSeeds = await seeds(); } catch { throw fail(); }
  const state = { driver, files: new Map(), sequence: 0, busy: false, attempted: false, cancelled: false,
    httpScope: Object.freeze({}), aborter: new AbortController(),
    inspectionAttempted: false, helper: null, closeDispatched: false, closeAcknowledged: false, closed: false,
    seedCount: 0, uniqueVoteBaseline: null, conversationReadback: false, completed: false };
  try {
    state.directory = await mkdtemp(join(await realpath(tmpdir()), 'fncp-fresh-bootstrap-')); await chmod(state.directory, 0o700); state.stamp = stamp(await lstat(state.directory));
    await write(state, 'ownership.json', { classification: 'INJECTED_PROTOCOL_ONLY', seedSha256: SEED_SHA, replayAllowed: false });
  } catch { throw fail(); }
  const summary = () => freeze({ classification: 'INJECTED_PROTOCOL_ONLY', actualRuntime: 'NOT_RUN', ordinaryImageApproval: 'NOT_ESTABLISHED',
    attempted: state.attempted, cancelled: state.cancelled, seedResponses: state.seedCount,
    latestUniqueSeedOwnerVotes: state.uniqueVoteBaseline, rawVoteHistory: 'NOT_CHECKED',
    closedConversationReadback: state.conversationReadback, helperClosure: state.closed ? 'INJECTED_READBACK_ACCEPTED' : 'NOT_VERIFIED',
    completed: state.completed, activationGranted: false, roundOpen: false, privateEvidencePreserved: true, ledgerEntries: state.sequence });
  return Object.freeze({
    privateDirectory: state.directory,
    summary() { if (arguments.length) throw fail(); return summary(); },
    cancel() { if (arguments.length) throw fail(); state.cancelled = true; state.aborter.abort(); return summary(); },
    async verifyIntegrity() { if (arguments.length || state.busy) throw fail(); try { await integrity(state); return true; } catch { throw fail(); } },
    async close() {
      if (arguments.length) throw fail(); state.cancelled = true; state.aborter.abort();
      if (state.busy) throw fail(); state.busy = true;
      try { await finishHelper(state); return summary(); } catch { throw fail(); } finally { state.busy = false; }
    },
    async run() {
      if (arguments.length || state.busy || state.attempted || state.cancelled) throw fail();
      state.busy = true; state.attempted = true;
      let result; let failed = false;
      try {
        // Even a first authenticated GET can create an OIDC user/mapping. This
        // durable marker precedes every driver callback, including readiness.
        await record(state, 'BOOTSTRAP_ATTEMPTED_BEFORE_ANY_DRIVER_CALL');
        if (state.cancelled) throw fail(); state.inspectionAttempted = true;
        state.helper = helper(await call(state, 'inspect-helper', {}));
        await record(state, 'HELPER_INJECTED_ID_CAPTURED', state.helper);
        const created = response(await call(state, 'create-conversation', {
          topic: 'FNCP Option C fresh disposable access QA', description: 'Synthetic local test only. No genuine participant data.',
          is_active: true, is_anon: true, is_draft: false, is_data_open: false, topics_enabled: false,
          treevite_enabled: false, strict_moderation: true, profanity_filter: false, spam_filter: false,
        }));
        const conversationId = conversation(created); await record(state, 'CONVERSATION_RESPONSE_CAPTURED', { conversationId });
        const ids = []; let pid;
        for (const txt of fixedSeeds) {
          await record(state, 'SEED_MUTATION_ATTEMPTED', { index: ids.length });
          const seeded = response(await call(state, 'create-seed', { conversation_id: conversationId, txt, is_seed: true }));
          if (!seeded || Array.isArray(seeded) || !integer(seeded.tid) || !integer(seeded.currentPid) || ids.includes(seeded.tid) || (pid !== undefined && pid !== seeded.currentPid)) throw fail();
          ids.push(seeded.tid); pid = seeded.currentPid; state.seedCount = ids.length;
          await record(state, 'SEED_RESPONSE_CAPTURED', { index: ids.length - 1, tid: seeded.tid });
        }
        const binding = validateFreshBootstrapResult({ conversationId, statementIds: ids });
        // Read while the exact owner can still traverse the ordinary comments
        // route; a later XID whitelist would deny a non-XID owner there.
        const rows = response(await call(state, 'read-seeds', { conversationId }));
        if (!Array.isArray(rows) || rows.length !== 15 || new Set(rows.map(row => row?.tid)).size !== 15) throw fail();
        for (let i = 0; i < 15; i++) {
          const row = rows.find(row => row?.tid === ids[i]);
          if (!row || row.conversation_id !== conversationId || row.txt !== fixedSeeds[i] || row.is_seed !== true || row.pid !== pid || row.mod !== 1 || row.active !== true ||
              row.agree_count !== 0 || row.disagree_count !== 0 || row.pass_count !== 1 || row.count !== 1) throw fail();
        }
        state.uniqueVoteBaseline = 15; await record(state, 'LATEST_UNIQUE_SEED_VOTE_BASELINE_READBACK', { seedOwnerPassVotes: 15, rawHistory: 'NOT_CHECKED' });
        await record(state, 'CONVERSATION_CLOSE_AND_WHITELIST_ATTEMPTED');
        const updated = response(await call(state, 'close-conversation', { conversation_id: conversationId, is_active: false, use_xid_whitelist: true, xid_required: true, send_created_email: false }));
        if (conversation(updated) !== conversationId) throw fail();
        const checked = response(await call(state, 'read-conversation', { conversationId }));
        if (conversation(checked) !== conversationId || checked.is_owner !== true || checked.is_active !== false || checked.use_xid_whitelist !== true ||
            checked.xid_required !== true || checked.is_data_open !== false || checked.strict_moderation !== true || checked.is_anon !== true || checked.is_draft !== false ||
            ['topics_enabled', 'treevite_enabled', 'profanity_filter', 'spam_filter'].some(key => checked[key] !== false)) throw fail();
        state.conversationReadback = true; await record(state, 'CLOSED_CONVERSATION_INJECTED_READBACK');
        result = freeze({ binding, evidence: 'INJECTED_PROTOCOL_ONLY', latestUniqueSeedOwnerVotes: 15, rawVoteHistory: 'NOT_CHECKED', roundOpen: false, activationGranted: false });
      } catch { failed = true; }
      finally {
        try { await finishHelper(state); } catch { failed = true; }
      }
      try {
        if (failed || state.cancelled || !state.closed || !result) throw fail();
        await record(state, 'PROTOCOL_COMPLETE_INJECTED_READBACK_ONLY');
        if (state.cancelled) throw fail(); state.completed = true; return result;
      } catch { throw fail(); } finally { state.busy = false; }
    },
  });
}
