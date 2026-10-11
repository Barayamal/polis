// Explicit local-only collector. Does not build, deploy, open a port, or inspect
// user volumes. Docker/scanner downloads are reads; outputs contain no users.
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { createHash } from 'node:crypto';

const [socket, imageId, output] = process.argv.slice(2);
if (process.argv.length !== 5 || !/^unix:\/\/\/Users\/[A-Za-z0-9._/-]+\/docker\.sock$/u.test(socket ?? '')
  || !/^sha256:[a-f0-9]{64}$/u.test(imageId ?? '') || !output?.startsWith('/') || resolve(output) !== output) {
  throw Error('Usage: node collect-candidate.mjs unix:///absolute/task/docker.sock sha256:EXACT_IMAGE_ID /new/output');
}
process.umask(0o077);
mkdirSync(output, { mode: 0o700 }); // existing evidence is never overwritten
const record = (name, value) => writeFileSync(join(output, name), value, { flag: 'wx', mode: 0o600 });
const run = (name, args, { input, network = false } = {}) => {
  const startedAt = new Date().toISOString();
  const result = spawnSync('docker', ['--host', socket, ...args], { encoding: 'utf8', input,
    maxBuffer: 128 * 1024 * 1024, timeout: 600_000 });
  record(`${name}.stdout`, result.stdout ?? ''); record(`${name}.stderr`, result.stderr ?? '');
  record(`${name}.result.json`, JSON.stringify({ startedAt, finishedAt: new Date().toISOString(),
    status: result.status, signal: result.signal, networkReadPermitted: network,
    error: result.error?.code ?? null }, null, 2) + '\n');
  if (result.status !== 0 || result.error) throw Error(`${name} failed; partial evidence retained.`);
  return result.stdout;
};

const info = JSON.parse(run('image-inspect', ['image', 'inspect', imageId]));
if (info.length !== 1 || info[0].Id !== imageId || info[0].Config.User !== '999:999'
  || info[0].Architecture !== 'arm64'
  || info[0].Config.Labels?.['org.barayamal.fncp.status'] !== 'UNRELEASED_LOCAL_CANDIDATE') throw Error('Unexpected candidate.');

run('packages', ['run', '--rm', '--pull=never', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
  '--security-opt', 'no-new-privileges', '--entrypoint', 'sh', imageId, '-euc',
  'test "$(id -u)" = 999; test ! -e /usr/local/bin/gosu; mariadbd --version; dpkg-query -W']);

const smoke = String.raw`set -eu
test "$(id -u)" = 999
mariadb-install-db --no-defaults --datadir=/var/lib/mysql --auth-root-authentication-method=normal --skip-test-db >/tmp/init.log 2>&1
server_pid=
trap 'test -z "$server_pid" || kill "$server_pid" 2>/dev/null || true' EXIT
start_db() {
  mariadbd --no-defaults --datadir=/var/lib/mysql --skip-networking --socket=/run/mysqld/test.sock --pid-file=/run/mysqld/test.pid --log-error=/tmp/server.log &
  server_pid=$!
  ready=0
  for attempt in $(seq 1 50); do
    if mariadb-admin --no-defaults --socket=/run/mysqld/test.sock -u root ping >/dev/null 2>&1; then ready=1; break; fi
    sleep 0.1
  done
  test "$ready" = 1 || { cat /tmp/server.log; exit 1; }
}
stop_db() {
  mariadb-admin --no-defaults --socket=/run/mysqld/test.sock -u root shutdown
  wait "$server_pid"
  server_pid=
}
start_db
mariadb --no-defaults --socket=/run/mysqld/test.sock -u root -e 'CREATE DATABASE synthetic_restart; CREATE TABLE synthetic_restart.receipts (id INT PRIMARY KEY, state VARCHAR(20) NOT NULL); INSERT INTO synthetic_restart.receipts VALUES (1,"approved"),(2,"revoked");'
test "$(mariadb --no-defaults --socket=/run/mysqld/test.sock -u root -N -e 'SELECT COUNT(*) FROM synthetic_restart.receipts')" = 2
stop_db
start_db
test "$(mariadb --no-defaults --socket=/run/mysqld/test.sock -u root -N -e 'SELECT COUNT(*) FROM synthetic_restart.receipts')" = 2
test "$(mariadb --no-defaults --socket=/run/mysqld/test.sock -u root -N -e 'SELECT state FROM synthetic_restart.receipts WHERE id=2')" = revoked
stop_db
printf '%s\n' '{"syntheticOnly":true,"freshDatadir":true,"socketOnly":true,"restartPreservedRows":2,"wordPressIntegration":false,"joinedRecovery":false}'
`;
run('database-smoke', ['run', '--rm', '--pull=never', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
  '--security-opt', 'no-new-privileges', '--pids-limit', '128', '--memory', '1g', '--cpus', '1',
  '--tmpfs', '/var/lib/mysql:rw,nosuid,nodev,noexec,uid=999,gid=999,mode=0700',
  '--tmpfs', '/run/mysqld:rw,nosuid,nodev,noexec,uid=999,gid=999,mode=0700',
  '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,mode=1777', '--entrypoint', 'sh', imageId, '-euc', smoke]);

const lock = JSON.parse(readFileSync(new URL('../image-security.lock.json', import.meta.url), 'utf8'));
const scanner = name => {
  const item = lock.scannerImages.find(x => x.name === name);
  if (!item || !/^sha256:[0-9a-f]{64}$/u.test(item.arm64Digest)) throw Error('Scanner lock invalid.');
  return item.tag.replace(/:[^/:]+$/u, '') + '@' + item.arm64Digest;
};
const syft = scanner('syft'), grype = scanner('grype');
record('scanner-lock.json', JSON.stringify({ syft, grype }, null, 2) + '\n');
run('pull-syft', ['pull', '--platform', 'linux/arm64', syft], { network: true });
run('pull-grype', ['pull', '--platform', 'linux/arm64', grype], { network: true });
const sbom = run('sbom', ['run', '--rm', '--pull=never', '--platform', 'linux/arm64', '--network', 'none',
  '-e', 'SYFT_CHECK_FOR_APP_UPDATE=false', '-v', '/var/run/docker.sock:/var/run/docker.sock', syft,
  'scan', `docker:${imageId}`, '-o', 'cyclonedx-json']);
JSON.parse(sbom); record('candidate.cdx.json', sbom);
const raw = run('scan', ['run', '--rm', '--pull=never', '--platform', 'linux/arm64', '-i',
  '-e', 'GRYPE_CHECK_FOR_APP_UPDATE=false', grype, '-o', 'json'], { input: sbom, network: true });
const scan = JSON.parse(raw), bySeverity = {}, ids = new Set();
for (const m of scan.matches) { bySeverity[m.vulnerability.severity] = (bySeverity[m.vulnerability.severity] ?? 0) + 1; ids.add(m.vulnerability.id); }
record('candidate.grype.json', raw);
record('summary.json', JSON.stringify({ status: 'COLLECTED_NOT_RELEASE_APPROVAL', recordedAt: new Date().toISOString(),
  imageId, architecture: info[0].Architecture, dockerfileSha256: info[0].Config.Labels['org.barayamal.fncp.candidate-dockerfile-sha256'],
  scanner: scan.descriptor, matches: scan.matches.length, bySeverity, uniqueVulnerabilities: ids.size,
  ignoredMatches: scan.ignoredMatches?.length ?? 0,
  newWordPressIntegration: false, newJoinedRecovery: false, publicDeployment: false }, null, 2) + '\n');
const checksums = readdirSync(output).sort().map(name => `${createHash('sha256').update(readFileSync(join(output, name))).digest('hex')}  ${name}`).join('\n') + '\n';
record('checksums.sha256', checksums);
process.stdout.write('Candidate evidence collected; see summary.json. This is not release approval.\n');
