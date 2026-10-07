/** Source-only fresh ownership foundation. Import performs no I/O.
 * No Docker, VM, source-acquisition, ordinary-bootstrap or networking adapter is
 * implemented here. Injected callbacks are trusted test/capability boundaries,
 * not evidence that a real runtime or egress policy was verified. Configuration
 * and callback inputs are private; only summary() is aggregate-safe. No adoption,
 * repeat after an uncertain mutation, deletion, activation or launch is offered.
 */
import { mkdtemp, chmod, realpath, lstat, open, readdir, link, unlink } from 'node:fs/promises';
import { constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, createHash, generateKeyPair } from 'node:crypto';
import { promisify } from 'node:util';
import { isProxy } from 'node:util/types';
import { validateFreshBootstrapResult } from '../fresh-bootstrap-result.mjs';

const CONTEXT = 'colima-fncp-c-20260913';
const PURPOSE = 'fresh-synthetic-foundation-only';
const IMAGES = Object.freeze({
  postgres: 'sha256:9d9684f7a95e94c9eb370212edea832e7b9916b7bd96b2821c5bc9cf63a0e8b3',
  server: 'sha256:07f8a21105ed90963ccdf0981d884323116187583a464bb581db14c621d33a98',
});
const PORTS = [5500, 8101, 8103, 33080];
const activeRequests = new WeakMap();
const sha = value => createHash('sha256').update(value).digest('hex');
const secret = () => randomBytes(32).toString('hex');
const fail = () => new Error('Fresh synthetic foundation boundary failed; new private state preserved.');
const frozen = value => {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) frozen(child);
    Object.freeze(value);
  }
  return value;
};
function exact(value, keys) {
  if (!value || typeof value !== 'object' || isProxy(value) || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Reflect.ownKeys(value).length !== keys.length) throw fail();
  const fields = Object.getOwnPropertyDescriptors(value);
  for (const key of keys) if (!fields[key] || !Object.hasOwn(fields[key], 'value')) throw fail();
  return Object.fromEntries(keys.map(key => [key, fields[key].value]));
}
function array(value, length) {
  if (!Array.isArray(value) || isProxy(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length !== length ||
      Reflect.ownKeys(value).length !== length + 1) throw fail();
  const fields = Object.getOwnPropertyDescriptors(value);
  return Array.from({ length }, (_, i) => {
    if (!fields[i] || !Object.hasOwn(fields[i], 'value')) throw fail();
    return fields[i].value;
  });
}
const stamp = info => ({ dev: info.dev, ino: info.ino, mode: info.mode, uid: info.uid });
const sameStamp = (info, expected) => ['dev', 'ino', 'mode', 'uid'].every(key => info[key] === expected[key]);
function regular(info) {
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || (info.mode & 0o777) !== 0o600) throw fail();
}
async function writeExclusive(state, name, contents) {
  const body = typeof contents === 'string' ? contents : JSON.stringify(contents, null, 2) + '\n';
  const handle = await open(join(state.directory, name), constants.O_CREAT | constants.O_EXCL |
    constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try {
    await handle.writeFile(body); await handle.sync();
    const info = await handle.stat(); regular(info);
    state.files.set(name, { ...stamp(info), digest: sha(body), size: info.size });
  } finally { await handle.close(); }
}
async function verify(state) {
  const directoryInfo = await lstat(state.directory);
  if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink() ||
      !sameStamp(directoryInfo, state.directoryStamp) || (directoryInfo.mode & 0o777) !== 0o700 ||
      await realpath(state.directory) !== state.directory) throw fail();
  const names = await readdir(state.directory);
  if (names.length !== state.files.size || names.some(name => !state.files.has(name))) throw fail();
  for (const [name, expected] of state.files) {
    const path = join(state.directory, name); const before = await lstat(path); regular(before);
    if (!sameStamp(before, expected) || before.size !== expected.size) throw fail();
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const info = await handle.stat(); regular(info);
      if (!sameStamp(info, expected) || sha(await handle.readFile()) !== expected.digest ||
          !sameStamp(await lstat(path), expected)) throw fail();
    } finally { await handle.close(); }
  }
}
/** Actual adapters may act only within the lifetime of a request emitted by this
 * new instance. Shape-copies, caller-selected names and later replay are rejected.
 * No private state or authority is returned. A stop latch invalidates new-work
 * requests but does not invalidate the narrowly scoped cleanup callback. */
export async function verifyFreshPolisRequest(request) {
  if (arguments.length !== 1 || !request || typeof request !== 'object' || isProxy(request)) throw fail();
  const record = activeRequests.get(request);
  if (!record || (record.state.stopRequested && !record.cleanup)) throw fail();
  try {
    await verify(record.state);
    if (activeRequests.get(request) !== record || (record.state.stopRequested && !record.cleanup)) throw fail();
  } catch { throw fail(); }
}
async function invoke(state, request, callback, cleanup = false) {
  activeRequests.set(request, { state, cleanup });
  try { return await callback(request); } finally { activeRequests.delete(request); }
}
async function record(state, operation, status, detail = {}) {
  await verify(state);
  const sequence = state.sequence + 1;
  await writeExclusive(state, `ledger-${String(sequence).padStart(4, '0')}.json`, {
    operation, status, ...detail,
  });
  state.sequence = sequence;
}
function spec(state, role) {
  return frozen({ role, name: state.names[role], imageId: IMAGES[role], os: 'linux', architecture: 'arm64',
    labels: state.labels, networkName: state.names.network,
    volumeName: role === 'postgres' ? state.names.volume : null,
    publishedPorts: role === 'server' ? [{ host: '127.0.0.1', port: 5500, containerPort: 5000 }] : [],
    pull: false, build: false, restart: 'no', egress: 'DENY_REQUIRED_NOT_IMPLEMENTED',
  });
}
function validatePreflight(state, value) {
  const result = exact(value, ['context', 'running', 'images', 'ports', 'resources']);
  if (result.context !== CONTEXT || result.running !== true) throw fail();
  const images = array(result.images, 2);
  for (const role of ['postgres', 'server']) {
    const matches = images.map(item => exact(item, ['role', 'id', 'os', 'architecture'])).filter(item => item.role === role);
    if (matches.length !== 1 || matches[0].id !== IMAGES[role] || matches[0].os !== 'linux' || matches[0].architecture !== 'arm64') throw fail();
  }
  const ports = array(result.ports, 4).map(item => exact(item, ['host', 'port', 'free']));
  for (const port of PORTS) if (ports.filter(item => item.port === port && item.host === '127.0.0.1' && item.free === true).length !== 1) throw fail();
  const resources = array(result.resources, 4).map(item => exact(item, ['kind', 'name', 'absent']));
  for (const [role, kind] of [['postgres', 'container'], ['server', 'container'], ['network', 'network'], ['volume', 'volume']]) {
    if (resources.filter(item => item.kind === kind && item.name === state.names[role] && item.absent === true).length !== 1) throw fail();
  }
}
function preflightRequest(state) {
  return frozen({ context: CONTEXT, startVm: false, pull: false, build: false,
    images: Object.entries(IMAGES).map(([role, id]) => ({ role, id, os: 'linux', architecture: 'arm64' })),
    ports: PORTS.map(port => ({ host: '127.0.0.1', port })),
    resources: [['postgres', 'container'], ['server', 'container'], ['network', 'network'], ['volume', 'volume']]
      .map(([role, kind]) => ({ kind, name: state.names[role] })),
  });
}
function validateContainer(state, role, value, expectedId = undefined, running = true) {
  const result = exact(value, ['id', 'name', 'imageId', 'labels', 'os', 'architecture', 'networkName',
    'volumeName', 'loopbackOnly', 'egressPolicyConfigured', 'running']);
  const labels = exact(result.labels, Object.keys(state.labels));
  if (typeof result.id !== 'string' || !/^[a-f0-9]{64}$/u.test(result.id) ||
      (expectedId !== undefined && result.id !== expectedId) || result.name !== state.names[role] ||
      result.imageId !== IMAGES[role] || result.os !== 'linux' || result.architecture !== 'arm64' ||
      Object.keys(state.labels).some(key => labels[key] !== state.labels[key]) ||
      result.networkName !== state.names.network || result.volumeName !== (role === 'postgres' ? state.names.volume : null) ||
      result.loopbackOnly !== true || result.egressPolicyConfigured !== true || result.running !== running) throw fail();
  return result.id;
}
async function atomicBinding(state, binding) {
  if (state.stopRequested) throw fail();
  const name = 'bound-config.json'; const pending = 'bound-config.pending.json';
  const config = { ...state.initial, environment: { ...state.initial.environment,
    FNCP_GATEWAY_CONVERSATION_ID: binding.conversationId,
    FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID: binding.conversationId,
    FNCP_SYNTHETIC_BOOTSTRAP_COMPLETE: 'true', FNCP_FIXED_STATEMENT_IDS: binding.statementIds.join(','),
  }, observedStatementIds: binding.statementIds, roundOpen: false, activationGranted: false,
  appliedToRuntime: false, bootstrapHelperClosure: 'NOT_VERIFIED', status: 'VALIDATED_INJECTED_RESULT_ONLY' };
  await writeExclusive(state, pending, config); await verify(state);
  if (state.stopRequested) throw fail();
  // link() publishes a complete same-directory file without replacing an existing
  // target. The transient second link is removed before recording new integrity.
  await link(join(state.directory, pending), join(state.directory, name));
  await unlink(join(state.directory, pending));
  const expected = state.files.get(pending); state.files.delete(pending); state.files.set(name, expected);
  await verify(state);
}

/** Creates new private material only; accepts no path, environment, configuration
 * or instance to adopt. privateDirectory is a private handoff, not log evidence. */
export async function createFreshPolisFoundation() {
  if (arguments.length !== 0) throw fail();
  const state = { files: new Map(), sequence: 0, busy: false, preflight: false, startAttempted: false,
    bootstrapAttempted: false, bound: false, stopRequested: false, resources: new Map() };
  try {
    const parent = await realpath(tmpdir());
    state.directory = await mkdtemp(join(parent, 'fncp-fresh-polis-')); await chmod(state.directory, 0o700);
    state.directoryStamp = stamp(await lstat(state.directory));
    const run = randomBytes(12).toString('hex');
    state.names = frozen({ run, project: `fncp-fresh-${run}`, postgres: `fncp-fresh-pg-${run}`,
      server: `fncp-fresh-api-${run}`, network: `fncp-fresh-net-${run}`, volume: `fncp-fresh-data-${run}` });
    state.labels = frozen({ 'org.barayamal.fncp.purpose': PURPOSE, 'org.barayamal.fncp.fresh-run': run });
    const values = { database: `synthetic_${run}`, databaseUser: `synthetic_${run}`, databasePassword: secret(),
      gatewaySecret: secret(), providerCredential: secret(), loginCodePepper: secret(), encryptionPassword: secret() };
    if (new Set([values.databasePassword, values.gatewaySecret, values.providerCredential,
      values.loginCodePepper, values.encryptionPassword]).size !== 5) throw fail();
    const pair = await promisify(generateKeyPair)('rsa', { modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
    const absentConversation = '9fncpBootstrap' + randomBytes(24).toString('hex');
    state.initial = frozen({ classification: 'SYNTHETIC_ONLY_NOT_RUN', context: CONTEXT,
      names: state.names, labels: state.labels, roundOpen: false, activationGranted: false, appliedToRuntime: false,
      topology: { network: state.names.network, internalRequired: true, additionalNetworksAllowed: false,
        egressImplementation: 'NOT_IMPLEMENTED', postgresVolume: state.names.volume },
      environment: {
        NODE_ENV: 'production', DEV_MODE: 'false', ENABLE_TELEMETRY: 'false', DATABASE_SSL: 'false',
        API_SERVER_PORT: '5000', API_PROD_HOSTNAME: '127.0.0.1:5500', DOMAIN_OVERRIDE: '127.0.0.1:5500',
        POLIS_JWT_ISSUER: 'http://127.0.0.1:5500/', POLIS_JWT_AUDIENCE: 'fncp-fresh-synthetic-only',
        RUN_PERIODIC_EXPORT_TESTS: 'false', SHOULD_USE_TRANSLATION_API: 'false', EMAIL_TRANSPORT_TYPES: '',
        ADMIN_EMAILS: '[]', ADMIN_UIDS: '[]', ADMIN_EMAIL_DATA_EXPORT: '', ADMIN_EMAIL_DATA_EXPORT_TEST: '',
        ADMIN_EMAIL_EMAIL_TEST: '', POLIS_FROM_ADDRESS: '', MAILGUN_API_KEY: '', MAILGUN_DOMAIN: '',
        AUTH_ISSUER: '', AUTH_DOMAIN: '', AUTH_AUDIENCE: '', AUTH_CLIENT_ID: '', AUTH_CLIENT_SECRET: '', JWKS_URI: '',
        AKISMET_ANTISPAM_API_KEY: '', ANTHROPIC_API_KEY: '', OPENAI_API_KEY: '', GEMINI_API_KEY: '',
        GOOGLE_CREDENTIALS_BASE64: '', GOOGLE_CREDS_STRINGIFIED: '', GOOGLE_APPLICATION_CREDENTIALS: '',
        AWS_ACCESS_KEY_ID: '', AWS_SECRET_ACCESS_KEY: '', AWS_REGION: '', AWS_EC2_METADATA_DISABLED: 'true',
        AWS_S3_ENDPOINT: '', AWS_S3_PUBLIC_ENDPOINT: '', AWS_S3_BUCKET_NAME: '', AWS_S3_JOB_BUCKET_NAME: '',
        SES_ENDPOINT: '', SQS_LOCAL_ENDPOINT: '', SQS_QUEUE_URL: '', DYNAMODB_ENDPOINT: '',
        DATABASE_URL: `postgres://${values.databaseUser}:${values.databasePassword}@${state.names.postgres}:5432/${values.database}`,
        FNCP_OPTION_C_RELEASE_MODE: 'production', FNCP_GATEWAY_ENFORCEMENT: 'true',
        FNCP_PROVIDER_ALLOWLIST_ENFORCEMENT: 'true', FNCP_GATEWAY_CONVERSATION_ID: absentConversation,
        FNCP_PROVIDER_ALLOWLIST_CONVERSATION_ID: absentConversation, FNCP_SYNTHETIC_BOOTSTRAP_COMPLETE: 'false', FNCP_FIXED_STATEMENT_IDS: '',
        FNCP_GATEWAY_SHARED_SECRET: values.gatewaySecret,
        FNCP_PROVIDER_ALLOWLIST_BEARER_CREDENTIAL: values.providerCredential,
        LOGIN_CODE_PEPPER: values.loginCodePepper, ENCRYPTION_PASSWORD_00001: values.encryptionPassword,
        JWT_PRIVATE_KEY_PATH: '/run/fncp/jwt-private.pem',
        JWT_PUBLIC_KEY_PATH: '/run/fncp/jwt-public.pem',
      },
    });
    await writeExclusive(state, 'ownership.json', { ...state.names, labels: state.labels, directory: state.directory,
      directoryStamp: state.directoryStamp, adapterStatus: 'NOT_IMPLEMENTED' });
    await writeExclusive(state, 'credentials.json', values);
    await writeExclusive(state, 'jwt-private.pem', pair.privateKey);
    await writeExclusive(state, 'jwt-public.pem', pair.publicKey);
    await writeExclusive(state, 'initial-config.json', state.initial);
    await verify(state);
  } catch { throw fail(); }

  const summary = () => frozen({ classification: 'SYNTHETIC_FOUNDATION_ONLY', actualRuntime: 'NOT_RUN',
    dockerAdapter: 'NOT_IMPLEMENTED', ordinaryBootstrapAdapter: 'NOT_IMPLEMENTED', sourceAcquisition: 'NOT_IMPLEMENTED',
    actualEgressAssurance: 'NOT_RUN', preflight: state.preflight ? 'INJECTED_PROBE_ACCEPTED' : 'NOT_ACCEPTED',
    startAttempted: state.startAttempted, bootstrapAttempted: state.bootstrapAttempted,
    conversationBound: state.bound, boundConfigurationApplied: false, roundOpen: false, activationGranted: false,
    containerAttempts: state.resources.size, verifiedContainers: [...state.resources.values()].filter(item => item.id).length,
    stoppedContainers: [...state.resources.values()].filter(item => item.stopped).length,
    uncertainContainers: [...state.resources.values()].filter(item => (item.dispatched && !item.id) || (item.stopAttempted && !item.stopped)).length,
    stopRequested: state.stopRequested, ledgerEntries: state.sequence, filesPreserved: true });
  const run = async (kind, input, operation) => {
    if (state.busy) throw fail(); state.busy = true;
    try {
      const value = exact(input, [kind]); if (typeof value[kind] !== 'function' || isProxy(value[kind])) throw fail();
      await verify(state); return await operation(value[kind]);
    } catch { throw fail(); } finally { state.busy = false; }
  };
  return Object.freeze({
    privateDirectory: state.directory,
    summary() { if (arguments.length !== 0) throw fail(); return summary(); },
    // Denial-only coordination for independently owned concrete adapters. This
    // does not stop a process: cancel admission first, then await adapter.close().
    cancel() { if (arguments.length !== 0) throw fail(); state.stopRequested = true; return summary(); },
    async verifyIntegrity() {
      if (arguments.length !== 0 || state.busy) throw fail();
      try { await verify(state); return true; } catch { throw fail(); }
    },
    async preflight(input) {
      if (arguments.length !== 1) throw fail();
      return run('probe', input, async probe => {
        if (state.startAttempted || state.stopRequested) throw fail();
        state.preflight = false; state.probe = undefined;
        const result = await invoke(state, preflightRequest(state), probe);
        validatePreflight(state, result); await verify(state);
        if (state.stopRequested) throw fail();
        state.probe = probe; state.preflight = true; return summary();
      });
    },
    async start(input) {
      if (arguments.length !== 1) throw fail();
      return run('driver', input, async driver => {
        if (!state.preflight || state.startAttempted || state.stopRequested) throw fail();
        // Repeat the same scoped read-only probe immediately before mutation;
        // this is not a race-proof reservation or a substitute for exclusive creation.
        state.preflight = false;
        validatePreflight(state, await invoke(state, preflightRequest(state), state.probe)); await verify(state);
        if (state.stopRequested) throw fail();
        state.preflight = true;
        state.startAttempted = true;
        for (const role of ['postgres', 'server']) {
          if (state.stopRequested) throw fail();
          const resource = { role, id: null, dispatched: false, stopAttempted: false, stopped: false }; state.resources.set(role, resource);
          await record(state, 'start', 'ATTEMPTED', { role, name: state.names[role] });
          if (state.stopRequested) throw fail(); resource.dispatched = true;
          const result = await invoke(state, frozen({ operation: 'start', context: CONTEXT, resource: spec(state, role),
            privateDirectory: state.directory, configurationFile: join(state.directory, 'initial-config.json') }), driver);
          const id = validateContainer(state, role, result);
          if ([...state.resources.values()].some(item => item.id === id)) throw fail();
          resource.id = id; await verify(state);
          await record(state, 'start', 'VERIFIED_INJECTED_RESULT', { role, id: resource.id });
          if (state.stopRequested) throw fail();
        }
        return summary();
      });
    },
    async bootstrap(input) {
      if (arguments.length !== 1) throw fail();
      return run('driver', input, async driver => {
        if (state.bootstrapAttempted || state.stopRequested || state.resources.size !== 2 ||
            [...state.resources.values()].some(item => !item.id)) throw fail();
        state.bootstrapAttempted = true;
        await record(state, 'bootstrap', 'ATTEMPTED');
        if (state.stopRequested) throw fail();
        const result = await invoke(state, frozen({ operation: 'bootstrap', context: CONTEXT,
          privateDirectory: state.directory, databaseContainer: state.resources.get('postgres').id,
          ordinaryBootstrapImage: 'NOT_PINNED', runtimeAdapter: 'NOT_IMPLEMENTED', launchAuthority: false }), driver);
        if (state.stopRequested) throw fail();
        const binding = validateFreshBootstrapResult(result); await verify(state);
        await atomicBinding(state, binding);
        if (state.stopRequested) throw fail(); state.bound = true;
        await record(state, 'bootstrap', 'VALIDATED_INJECTED_RESULT_ONLY', { statementCount: binding.statementIds.length });
        return summary();
      });
    },
    async stop(input) {
      if (arguments.length !== 1) throw fail();
      // Valid closure requests latch synchronously, including during a pending
      // callback. Busy calls reject (avoiding reentrant-callback deadlocks), but
      // prevent late startup/bootstrap progress. Retry stop after that operation
      // settles to dispatch only verified IDs; uncertain stop attempts never replay.
      const value = exact(input, ['driver']);
      if (typeof value.driver !== 'function' || isProxy(value.driver)) throw fail();
      state.stopRequested = true;
      return run('driver', input, async driver => {
        let failed = false;
        for (const role of ['server', 'postgres']) {
          const resource = state.resources.get(role);
          if (!resource || !resource.dispatched || resource.stopped) continue;
          if (!resource.id || resource.stopAttempted) { failed = true; continue; }
          resource.stopAttempted = true;
          try {
            await record(state, 'stop', 'ATTEMPTED', { role, id: resource.id });
            const request = frozen({ operation: 'inspect-before-stop', context: CONTEXT, resource: spec(state, role), id: resource.id });
            validateContainer(state, role, await invoke(state, request, driver, true), resource.id); await verify(state);
            const result = await invoke(state, frozen({ ...request, operation: 'stop' }), driver, true);
            validateContainer(state, role, result, resource.id, false); await verify(state);
            resource.stopped = true;
            await record(state, 'stop', 'VERIFIED_INJECTED_RESULT', { role, id: resource.id });
          } catch { failed = true; }
        }
        if (failed) throw fail(); return summary();
      });
    },
  });
}
