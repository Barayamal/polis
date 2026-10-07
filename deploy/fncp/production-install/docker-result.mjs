import { createHash } from 'node:crypto';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const kinds = new Set(['container', 'network', 'volume']);
const nameOk = value => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u.test(value);
const boundedText = bytes => Buffer.isBuffer(bytes) && bytes.length <= 8192
  && Buffer.from(bytes.toString('utf8')).equals(bytes) ? bytes.toString('utf8').trim() : null;

/** An inspect error proves absence only when Docker identifies the exact kind
 * and target. Daemon, socket, permission and malformed responses are unknown. */
export function dockerAbsenceVerdict(kind, name, result) {
  if (!kinds.has(kind) || !nameOk(name) || !result || result.overflow
    || result.termination && result.termination !== 'exit') return 'unconfirmed';
  if (result.code === 0) return 'present';
  if (result.code !== 1 || boundedText(result.stdout) !== '[]') return 'unconfirmed';
  const stderr = boundedText(result.stderr);
  const messages = {
    container: ['No such container: ' + name, 'No such object: ' + name],
    network: ['network ' + name + ' not found', 'No such network: ' + name],
    volume: ['No such volume: ' + name, 'get ' + name + ': no such volume'],
  }[kind];
  return ['Error response from daemon: ', 'Error: '].some(prefix => messages.some(message => stderr === prefix + message))
    ? 'absent' : 'unconfirmed';
}

const operations = new Set(['info', 'inspect', 'ps', 'run', 'exec', 'stop',
  'volume-create', 'volume-rm', 'network-create', 'compose-run', 'compose-up', 'compose-ps', 'compose']);
/** Deliberately contains no argv, stdin, path or raw output. Engine and child
 * errors can echo credentials; fixed categories and hashes are the only export. */
export function dockerFailureDiagnostic({ operation, phase, result, absence }) {
  if (!operations.has(operation) || typeof phase !== 'string' || !/^[a-z][a-z0-9-]{0,95}$/u.test(phase)
    || !result || !Buffer.isBuffer(result.stdout) || !Buffer.isBuffer(result.stderr)
    || absence !== undefined && !['present', 'unconfirmed'].includes(absence)) throw new Error('FNCP_DOCKER_DIAGNOSTIC_REJECTED');
  const text = Buffer.concat([result.stdout, result.stderr]).subarray(0, 8 * 1024 * 1024).toString('utf8');
  const termination = ['exit','timeout','output-limit','spawn-error','signal'].includes(result.termination)
    ? result.termination : result.overflow ? 'output-limit' : result.code === null ? 'signal' : 'exit';
  let category = absence === 'present' ? 'resource-already-present' : 'unclassified-command-failure';
  if (termination !== 'exit') category = termination;
  else if (/(?:cannot connect to (?:the )?docker daemon|error during connect|failed to connect to (?:the )?docker|dial unix|is the docker daemon running)/iu.test(text)) category = 'engine-connection-failed';
  else if (/(?:permission denied|access denied|unauthorized|operation not permitted)/iu.test(text)) category = 'permission-denied';
  else if (/(?:invalid mount|error while mounting|failed to mount|mounts denied|bind source path does not exist|invalid subpath)/iu.test(text)) category = 'mount-failed';
  else if (/(?:is unhealthy|unhealthy container|dependency failed to start|did not become healthy|timed out waiting)/iu.test(text)) category = 'service-readiness-failed';
  else if (/(?:OCI runtime create failed|failed to create task|exec format error|executable file not found)/iu.test(text)) category = 'container-start-failed';
  else if (/(?:additional propert(?:y|ies).*not allowed|invalid compose|validating .*services|unknown flag|unknown command)/iu.test(text)) category = 'descriptor-or-cli-rejected';
  else if (absence === 'unconfirmed') category = 'target-absence-unconfirmed';
  return Object.freeze({ profile: 'FNCP_DOCKER_FAILURE_V1', operation, phase, category,
    exitCode: Number.isSafeInteger(result.code) ? result.code : null, termination,
    ...(absence ? { absence } : {}),
    stdout: { bytes: result.stdout.length, sha256: sha(result.stdout) },
    stderr: { bytes: result.stderr.length, sha256: sha(result.stderr) } });
}
