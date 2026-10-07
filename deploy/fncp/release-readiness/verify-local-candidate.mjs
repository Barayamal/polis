// Reproducible local regression receipt. Runs only named synthetic test suites;
// no Docker command, provider preflight, outbound message or deployment action.
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, mkdirSync, writeFileSync, lstatSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const directories = [
  'production-service', 'production-identity', 'production-deployment',
  'production-deployment/wordpress-runtime', 'production-activation',
  'production-edge', 'production-install', 'release-readiness',
];
const [destination] = process.argv.slice(2);
if (process.argv.length !== 3 || !destination?.startsWith('/') || resolve(destination) !== destination) {
  throw Error('Usage: node verify-local-candidate.mjs /new/absolute/evidence-directory');
}
process.umask(0o077); mkdirSync(destination, { mode: 0o700 });
const save = (name, bytes) => writeFileSync(join(destination, name), bytes, { mode: 0o600, flag: 'wx' });
const tests = directories.flatMap(name => readdirSync(join(root, 'deploy/fncp', name))
  .filter(file => file.endsWith('.test.mjs')).map(file => `deploy/fncp/${name}/${file}`)).sort();
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function inventory() {
  const files = [];
  function visit(path, name) {
    for (const file of readdirSync(path).sort()) {
      if (file === 'node_modules' || file.startsWith('.')) continue;
      const absolute = join(path, file), relative = name + '/' + file, s = lstatSync(absolute);
      if (s.isSymbolicLink()) continue;
      if (s.isDirectory()) visit(absolute, relative);
      else if (s.isFile() && /\.(mjs|js|php|json|md|sh|sql)$/u.test(file)) files.push({ path: relative, sha256: hash(readFileSync(absolute)) });
    }
  }
  // These are repository source files, not runtime/registration storage.
  visit(join(root, 'deploy/fncp'), 'deploy/fncp');
  return files;
}
const before = inventory();
const began = new Date().toISOString();
const result = spawnSync(process.execPath, ['--test', '--test-reporter=tap', ...tests], {
  cwd: root, encoding: 'utf8', timeout: 300_000, maxBuffer: 32 * 1024 * 1024,
});
save('tests.tap', result.stdout ?? ''); save('tests.stderr', result.stderr ?? '');
const totals = Object.fromEntries(['tests','suites','pass','fail','cancelled','skipped','todo'].map(key =>
  [key, Number((result.stdout ?? '').match(new RegExp(`^# ${key} (\\d+)$`, 'm'))?.[1] ?? NaN)]));
const unchanged = JSON.stringify(before) === JSON.stringify(inventory());
const passed = result.status === 0 && !result.error && unchanged && totals.tests > 0
  && totals.tests === totals.pass && ['fail','cancelled','skipped','todo'].every(k => totals[k] === 0);
save('source-manifest.json', JSON.stringify(before, null, 2) + '\n');
const summary = { status: passed ? 'PASS_LOCAL_SYNTHETIC_ONLY' : 'FAIL', began,
  completedAt: new Date().toISOString(), node: process.version, testFiles: tests.length,
  totals, processStatus: result.status, signal: result.signal, error: result.error?.code ?? null,
  sourceUnchangedDuringRun: unchanged, sourceManifestSha256: hash(JSON.stringify(before, null, 2) + '\n'),
  realProviderValidated: false, publicHttpsValidated: false, joinedRuntimeRebuilt: false, deploymentAuthorized: false };
save('summary.json', JSON.stringify(summary, null, 2) + '\n');
process.stdout.write(JSON.stringify(summary, null, 2) + '\n');
if (!passed) process.exitCode = 1;
