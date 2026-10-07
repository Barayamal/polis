// Test support only. Creates an ephemeral CA and CA:false loopback server leaf;
// no retained credentials and no modification to the system trust store.
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export function freshLeaf({ purpose = 'serverAuth' } = {}) {
  if (!['serverAuth', 'clientAuth'].includes(purpose)) throw Error('Ephemeral edge TLS fixture purpose rejected.');
  const directory = mkdtempSync(join(tmpdir(), 'fncp-edge-test-')); chmodSync(directory, 0o700);
  const run = (args, input) => {
    const result = spawnSync('openssl', args, { cwd: directory, input, stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 10_000, maxBuffer: 8192 });
    if (result.error || result.status !== 0) throw Error('Ephemeral edge TLS fixture failed.');
  };
  try {
    run(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-noenc', '-days', '1',
      '-subj', '/CN=Invented edge fixture CA', '-addext', 'basicConstraints=critical,CA:TRUE',
      '-keyout', 'ca-key.pem', '-out', 'ca.pem']);
    run(['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-noenc',
      '-subj', '/CN=Invented edge fixture leaf', '-keyout', 'leaf-key.pem', '-out', 'leaf.csr']);
    run(['x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca-key.pem', '-CAcreateserial', '-days', '1',
      '-extfile', '/dev/stdin', '-out', 'leaf.pem'],
    `subjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=${purpose}\n`);
    for (const name of ['ca-key.pem', 'leaf-key.pem']) chmodSync(join(directory, name), 0o600);
    return { tls: { key: readFileSync(join(directory, 'leaf-key.pem')), cert: readFileSync(join(directory, 'leaf.pem')) },
      ca: readFileSync(join(directory, 'ca.pem')) };
  } finally { rmSync(directory, { recursive: true, force: true }); }
}
