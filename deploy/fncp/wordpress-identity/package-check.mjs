#!/usr/bin/env node
/** Offline source-closure check, NOT an installer or deployable plugin release.
 * Imports start nothing. Reads only five explicit source files; never traverses
 * runtime directories, executes PHP, writes archives or changes fixture guards.
 * The small PHP lexer deliberately accepts only the reviewed literal dependency
 * form. This is dependency packaging validation, not PHP security certification.
 */
import { createHash } from 'node:crypto';
import { constants, closeSync, fstatSync, lstatSync, openSync, readFileSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, join, parse, posix, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const FNCP_DIRECTORY = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const WORDPRESS_ENTRY = 'wordpress-identity/fncp-wordpress-identity.php';
const GRAPH = Object.freeze({
  'wordpress-identity/contract.php': Object.freeze(['wordpress-local/contract.php']),
  'wordpress-identity/fncp-wordpress-identity.php': Object.freeze(['wordpress-identity/registry.php', 'wordpress-local/journal.php']),
  'wordpress-identity/registry.php': Object.freeze(['wordpress-identity/contract.php']),
  'wordpress-local/contract.php': Object.freeze([]),
  'wordpress-local/journal.php': Object.freeze(['wordpress-local/contract.php']),
});
export const WORDPRESS_FILES = Object.freeze(Object.keys(GRAPH));
const MAX_FILE_BYTES = 65_536;
const MAX_TOTAL_BYTES = 262_144;
const failure = () => new Error('WordPress source closure rejected.');
const need = condition => { if (!condition) throw failure(); };
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

/** Bounded lexer for the existing PHP source subset. String/comment contents
 * never become include statements. Complex interpolation, heredocs, inline HTML
 * and command strings are rejected rather than guessed. */
function tokens(source) {
  need(typeof source === 'string' && source.startsWith('<?php\n') && !source.includes('\0') &&
    !source.includes('?>') && !source.slice(5).includes('<?'));
  const result = []; let i = 5;
  while (i < source.length) {
    const c = source[i];
    if (/\s/u.test(c)) { i++; continue; }
    if (source.startsWith('//', i) || c === '#' && source[i + 1] !== '[') {
      const end = source.indexOf('\n', i); i = end === -1 ? source.length : end + 1; continue;
    }
    if (source.startsWith('/*', i)) {
      const end = source.indexOf('*/', i + 2); need(end !== -1); i = end + 2; continue;
    }
    need(c !== '`' && !source.startsWith('<<<', i) && !source.startsWith('#[', i));
    if (c === "'" || c === '"') {
      const start = i++; let closed = false;
      while (i < source.length) {
        if (source[i] === '\\') { i += 2; continue; }
        if (source[i] === c) { i++; closed = true; break; }
        // The only complex interpolation in the reviewed sources is a simple
        // WordPress property read. No expression/call/include may hide here.
        if (c === '"' && source.startsWith('${', i)) throw failure();
        if (c === '"' && source.startsWith('{$', i)) {
          const end = source.indexOf('}', i); need(end !== -1);
          need(/^\{\$[A-Za-z_][A-Za-z0-9_]*(?:->[A-Za-z_][A-Za-z0-9_]*)?\}$/u.test(source.slice(i, end + 1)));
          i = end + 1; continue;
        }
        i++;
      }
      need(closed);
      result.push({ kind: 'string', raw: source.slice(start, i) }); continue;
    }
    const word = /^[A-Za-z_][A-Za-z0-9_]*/u.exec(source.slice(i));
    if (word) { result.push({ kind: 'word', raw: word[0] }); i += word[0].length; continue; }
    need(c.charCodeAt(0) < 128); // Unknown identifiers/syntax require review.
    result.push({ kind: 'punctuation', raw: c }); i++;
  }
  return result;
}

function dependencies(path, source) {
  const lexed = tokens(source); const found = [];
  for (let i = 0; i < lexed.length; i++) {
    const token = lexed[i]; if (token.kind !== 'word') continue;
    const word = token.raw.toLowerCase();
    need(!['eval', '__halt_compiler', 'create_function'].includes(word));
    if (!['require', 'require_once', 'include', 'include_once'].includes(word)) continue;
    need(word === 'require_once' && lexed[i + 1]?.raw === '__DIR__' &&
      lexed[i + 2]?.raw === '.' && lexed[i + 3]?.kind === 'string' && lexed[i + 4]?.raw === ';');
    const literal = lexed[i + 3].raw;
    // No escaping, interpolation, stream wrappers, absolute path or aliases.
    need(/^'\/(?:\.\.\/)?[a-z][a-z0-9-]*(?:\/[a-z][a-z0-9-]*)?\.php'$/u.test(literal));
    const suffix = literal.slice(2, -1);
    const target = posix.normalize(posix.join(posix.dirname(path), suffix));
    need(!target.startsWith('../') && Object.hasOwn(GRAPH, target) && !found.includes(target));
    found.push(target); i += 4;
  }
  found.sort();
  need(JSON.stringify(found) === JSON.stringify([...GRAPH[path]].sort()));
  return found;
}

/** Pure validation of an in-memory map in the original sibling layout. Only
 * source code is accepted, not test/runtime/operator/configuration files. */
export function validateWordPressBundle(files) {
  try {
    need(files instanceof Map && files.size === WORDPRESS_FILES.length &&
      [...files.keys()].every(path => typeof path === 'string' && Object.hasOwn(GRAPH, path)));
    let totalBytes = 0;
    const manifestFiles = WORDPRESS_FILES.map(path => {
      const source = files.get(path); need(typeof source === 'string');
      const bytes = Buffer.byteLength(source); totalBytes += bytes;
      need(bytes > 0 && bytes <= MAX_FILE_BYTES && totalBytes <= MAX_TOTAL_BYTES);
      // Config/key files cannot enter the map. Recognisable accidentally pasted
      // private-key material is rejected too; this is not a general secret scan.
      need(!/-----BEGIN [A-Z ]*PRIVATE KEY-----/u.test(source));
      const requires = dependencies(path, source);
      return { sourcePath: 'deploy/fncp/' + path, bundlePath: path, bytes, sha256: hash(source), requires };
    });
    const reached = new Set();
    const visit = path => { if (reached.has(path)) return; reached.add(path); for (const child of GRAPH[path]) visit(child); };
    visit(WORDPRESS_ENTRY); need(reached.size === WORDPRESS_FILES.length);
    return Object.freeze({ schemaVersion: 1, mode: 'SYNTHETIC_ONLY', outcome: 'KEEP_CLOSED',
      check: 'OFFLINE_SOURCE_DEPENDENCY_CLOSURE', closureComplete: true,
      productionReady: false, deployablePackage: false, archiveWritten: false,
      sourceExecuted: false, networkUsed: false, sourceModified: false,
      entrypoint: WORDPRESS_ENTRY, fileCount: manifestFiles.length,
      dependencyCount: manifestFiles.reduce((count, file) => count + file.requires.length, 0),
      sourceClosureSha256: hash(JSON.stringify(manifestFiles)), files: manifestFiles,
      limitations: ['not-a-php-security-audit', 'not-a-general-secret-scan', 'not-a-production-plugin',
        'wordpress-core-and-host-runtime-not-included', 'synthetic-guards-not-removed', 'no-install-or-activation'] });
  } catch { throw failure(); }
}

function plainDirectory(path) {
  need(isAbsolute(path) && resolve(path) === path && realpathSync(path) === path);
  const root = parse(path).root; let current = root;
  for (const part of path.slice(root.length).split('/').filter(Boolean)) {
    current = join(current, part); const stat = lstatSync(current);
    need(stat.isDirectory() && !stat.isSymbolicLink());
  }
}

/** Read only the exact five source paths into a fresh in-memory map. A caller
 * may pass an explicit isolated test directory; the CLI has no path override.
 * Source metadata is rechecked; this is not a hostile concurrent-writer sandbox.
 */
export function assembleWordPressBundle(sourceDirectory = FNCP_DIRECTORY) {
  try {
    need(typeof sourceDirectory === 'string'); plainDirectory(sourceDirectory);
    const files = new Map();
    for (const path of WORDPRESS_FILES) {
      const full = join(sourceDirectory, path); plainDirectory(dirname(full));
      const before = lstatSync(full);
      need(before.isFile() && !before.isSymbolicLink() && before.nlink === 1 &&
        before.size > 0 && before.size <= MAX_FILE_BYTES && realpathSync(full) === full);
      let fd;
      try {
        fd = openSync(full, constants.O_RDONLY | constants.O_NOFOLLOW);
        const opened = fstatSync(fd); need(opened.dev === before.dev && opened.ino === before.ino && opened.nlink === 1);
        const bytes = readFileSync(fd); const after = fstatSync(fd); const current = lstatSync(full);
        need(after.isFile() && after.nlink === 1 && bytes.length === before.size &&
          after.size === before.size && after.mtimeMs === before.mtimeMs && after.ctimeMs === before.ctimeMs &&
          current.dev === before.dev && current.ino === before.ino && current.isFile() && current.nlink === 1 &&
          current.size === before.size && current.mtimeMs === before.mtimeMs && current.ctimeMs === before.ctimeMs &&
          !current.isSymbolicLink() && realpathSync(full) === full);
        const source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        need(Buffer.from(source).equals(bytes)); files.set(path, source);
      } finally { if (fd !== undefined) closeSync(fd); }
    }
    return { files, manifest: validateWordPressBundle(files) };
  } catch { throw failure(); }
}

const invoked = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invoked) {
  try {
    need(process.argv.length === 3 && process.argv[2] === '--check');
    console.log(JSON.stringify(assembleWordPressBundle().manifest, null, 2));
  } catch {
    console.error('WordPress source closure rejected; KEEP_CLOSED. No archive, install or activation performed.');
    process.exitCode = 1;
  }
}
