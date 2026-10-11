import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { dockerAbsenceVerdict, dockerFailureDiagnostic } from './docker-result.mjs';

const name = 'fncp-native-02_participant_ingress';
const result = (stderr, extra = {}) => ({ code: 1, stdout: Buffer.from('[]\n'),
  stderr: Buffer.from(stderr + '\n'), overflow: false, termination: 'exit', ...extra });
const missing = 'Error response from daemon: network ' + name + ' not found';

test('current Docker network inspect absence identifies the exact target', () => {
  assert.equal(dockerAbsenceVerdict('network', name, result(missing)), 'absent');
});
test('supported kind-specific inspect absence forms remain compatible', () => {
  for (const [kind, message] of [
    ['container', 'Error: No such object: ' + name],
    ['container', 'Error response from daemon: No such container: ' + name],
    ['volume', 'Error response from daemon: get ' + name + ': no such volume'],
    ['volume', 'Error response from daemon: No such volume: ' + name],
    ['network', 'Error response from daemon: No such network: ' + name],
  ]) assert.equal(dockerAbsenceVerdict(kind, name, result(message)), 'absent');
});
test('an existing inspected resource is never absent', () => {
  assert.equal(dockerAbsenceVerdict('network', name, result('', { code: 0, stdout: Buffer.from('[{"Name":"'+name+'"}]') })), 'present');
});
test('different resource, kind or name case cannot establish target absence', () => {
  for (const [kind, target, message] of [
    ['network', name + '-other', missing],
    ['network', name.toUpperCase(), missing],
    ['container', name, missing],
    ['network', name, 'Error response from daemon: No such volume: ' + name],
  ]) assert.equal(dockerAbsenceVerdict(kind, target, result(message)), 'unconfirmed');
});
test('daemon, socket, permission and ambiguous not-found errors fail closed', () => {
  for (const message of [
    'Cannot connect to the Docker daemon at unix:///no/such/docker.sock. Is the docker daemon running?',
    'error during connect: dial unix /run/no-such/docker.sock: connect: no such file or directory',
    'Error response from daemon: permission denied',
    'Error response from daemon: network database not found',
    'network ' + name + ' not found',
    missing + '\nError response from daemon: permission denied',
    'Warning: server unavailable\n' + missing,
  ]) assert.equal(dockerAbsenceVerdict('network', name, result(message)), 'unconfirmed');
});
test('absence requires inspect empty-array output, exact failure exit and bounded UTF-8', () => {
  for (const extra of [
    { code: 125 }, { code: null }, { stdout: Buffer.alloc(0) },
    { stdout: Buffer.from('[{}]') }, { stdout: Buffer.from('null') },
    { stderr: Buffer.from([0xff]) }, { stderr: Buffer.alloc(8193, 32) },
  ]) assert.equal(dockerAbsenceVerdict('network', name, result(missing, extra)), 'unconfirmed');
});
test('termination or truncated output cannot prove absence even with matching text', () => {
  for (const extra of [{ overflow: true }, ...['timeout','output-limit','spawn-error','signal'].map(termination => ({ termination }))])
    assert.equal(dockerAbsenceVerdict('network', name, result(missing, extra)), 'unconfirmed');
});
test('invalid resource inputs fail closed', () => {
  for (const [kind, target] of [['image', name], ['network', name + '\n'], ['network', '--help'], ['network', 'x'.repeat(129)]])
    assert.equal(dockerAbsenceVerdict(kind, target, result(missing)), 'unconfirmed');
});
test('safe evidence retains phase and cause without engine or child secrets', () => {
  const secret = 'OIDC_PASSWORD=do-not-publish-example';
  const r = result('OCI runtime create failed: ' + secret, { stdout: Buffer.from('private@example.invalid ' + secret) });
  const evidence = dockerFailureDiagnostic({ operation: 'compose-run', phase: 'pg-initialize', result: r });
  assert.equal(evidence.category, 'container-start-failed');
  assert.equal(evidence.phase, 'pg-initialize');
  assert.equal(evidence.stderr.sha256, createHash('sha256').update(r.stderr).digest('hex'));
  assert.equal(evidence.stderr.bytes, r.stderr.length);
  for (const value of [secret, 'private@example.invalid', 'OCI runtime create failed']) assert.equal(JSON.stringify(evidence).includes(value), false);
});
test('safe evidence distinguishes absence uncertainty and resource collision', () => {
  const diagnostic = absence => dockerFailureDiagnostic({ operation: 'inspect', phase: 'image-and-namespace-preflight', result: result('unknown failure'), absence });
  assert.equal(diagnostic('unconfirmed').category, 'target-absence-unconfirmed');
  assert.equal(diagnostic('present').category, 'resource-already-present');
});
test('safe evidence classifies operational failures and bounded process termination', () => {
  for (const [message, category] of [
    ['Cannot connect to the Docker daemon', 'engine-connection-failed'],
    ['permission denied', 'permission-denied'],
    ['invalid mount config', 'mount-failed'],
    ['dependency failed to start: container is unhealthy', 'service-readiness-failed'],
    ['unknown flag: --wait', 'descriptor-or-cli-rejected'],
  ]) assert.equal(dockerFailureDiagnostic({ operation: 'compose-up', phase: 'start-native-databases', result: result(message) }).category, category);
  for (const termination of ['timeout','output-limit','spawn-error','signal']) {
    const evidence = dockerFailureDiagnostic({ operation: 'run', phase: 'stage-maintenance-material', result: result('secret', { code: null, termination }) });
    assert.equal(evidence.category, termination); assert.equal(evidence.exitCode, null);
  }
});
test('diagnostic metadata rejects free-form names and cannot smuggle raw output', () => {
  for (const extra of [{ operation: 'exec secret' }, { phase: '/private/secret' }, { absence: 'secret' }])
    assert.throws(() => dockerFailureDiagnostic({ operation: 'run', phase: 'pg-seed', result: result('secret'), ...extra }), /FNCP_DOCKER_DIAGNOSTIC_REJECTED/u);
});
