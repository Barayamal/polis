import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { canonical, exact } from '../production-service/contracts.mjs';
import { MAX_BYTES, volumeRoles, failure, privateInput, unchanged, exactly, write, inspectVolumeArchive } from './recovery-archive.mjs';
const magic = version => Buffer.from(version === 3 ? 'FNCPJOIN03' : version === 2 ? 'FNCPJOIN02' : 'FNCPJOIN01');
const profile = version => 'FNCP_JOINED_COLD_BUNDLE_V' + version;
const MAX_HEADER = 262144;

/** One bounded plaintext framing, encrypted in its entirety by AES-256-GCM.
 * The six mandatory durable volumes cannot be independently omitted/rebound.
 * Host material and private descriptors reside only in the encrypted metadata.
 */
export async function packRecoveryBundle({ archives, expectedInventories, metadata, targetPath, onCreated }) {
  let output;
  try {
    const version = metadata?.source?.imageLock?.version ?? 1, roles = volumeRoles(version), MAGIC = magic(version);
    exact(archives, roles);
    exact(expectedInventories, roles);
    const inventories = await Promise.all(roles.map(role => inspectVolumeArchive(archives[role], role)));
    if (inventories.some(i => i.archiveSha256 !== expectedInventories[i.role].archiveSha256 || i.contentSha256 !== expectedInventories[i.role].contentSha256)) throw failure();
    const header = { profile: profile(version), metadata,
      components: inventories.map(({ role, bytes, archiveSha256, contentSha256 }) => ({ role, bytes, archiveSha256, contentSha256 })) };
    const encoded = Buffer.from(canonical(header)), prefix = Buffer.alloc(MAGIC.length + 4);
    if (encoded.length > MAX_HEADER || prefix.length + encoded.length + inventories.reduce((n, i) => n + i.bytes, 0) > MAX_BYTES) throw failure();
    MAGIC.copy(prefix); prefix.writeUInt32BE(encoded.length, MAGIC.length);
    output = await fs.open(targetPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    onCreated?.(targetPath, await output.stat({ bigint: true }));
    const hash = createHash('sha256');
    const append = async b => { hash.update(b); await write(output, b); };
    await append(prefix); await append(encoded);
    for (const inventory of inventories) {
      const path = archives[inventory.role], opened = await privateInput(path), check = createHash('sha256');
      const chunk = Buffer.alloc(65536); let offset = 0;
      try { while (offset < inventory.bytes) { const bytes = chunk.subarray(0, Math.min(chunk.length, inventory.bytes - offset)); await exactly(opened.file, bytes, offset); check.update(bytes); await append(bytes); offset += bytes.length; }
        if (check.digest('hex') !== inventory.archiveSha256) throw failure(); await unchanged(path, opened);
      } finally { chunk.fill(0); await opened.file.close(); }
    }
    await output.sync(); return { bundleSha256: hash.digest('hex'), bytes: Number((await output.stat()).size), components: roles.length };
  } catch { throw failure(); } finally { await output?.close(); }
}

/** Call only after authenticated decryption. Component bytes are checked before
 * the fixed-role archive inspector grants extraction authority.
 */
export async function unpackRecoveryBundle({ sourcePath, directory, onCreated }) {
  let opened;
  try {
    opened = await privateInput(sourcePath); const prefix = Buffer.alloc(14);
    await exactly(opened.file, prefix, 0); const tag = prefix.subarray(0, 10).toString('ascii');
    if (!['FNCPJOIN01', 'FNCPJOIN02', 'FNCPJOIN03'].includes(tag)) throw failure();
    const version = Number(tag.slice(-2)), roles = volumeRoles(version), MAGIC = magic(version);
    const length = prefix.readUInt32BE(MAGIC.length); if (length < 1 || length > MAX_HEADER || length + prefix.length > Number(opened.stat.size)) throw failure();
    const encoded = Buffer.alloc(length); await exactly(opened.file, encoded, prefix.length);
    const header = JSON.parse(encoded.toString('utf8')); exact(header, ['profile', 'metadata', 'components']);
    if (header.profile !== profile(version) || canonical(header) !== encoded.toString('utf8')
      || !Array.isArray(header.components) || header.components.length !== roles.length) throw failure();
    if ((header.metadata?.source?.imageLock?.version ?? 1) !== version) throw failure();
    let position = prefix.length + length; const archives = {}, inventories = {};
    for (let i = 0; i < roles.length; i++) {
      const component = header.components[i]; exact(component, ['role', 'bytes', 'archiveSha256', 'contentSha256']);
      if (component.role !== roles[i] || !Number.isSafeInteger(component.bytes) || component.bytes < 1024 || component.bytes > MAX_BYTES
        || !/^[a-f0-9]{64}$/u.test(component.archiveSha256) || !/^[a-f0-9]{64}$/u.test(component.contentSha256)
        || position + component.bytes > Number(opened.stat.size)) throw failure();
      const path = join(directory, component.role + '.authenticated.tar');
      const output = await fs.open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
      const hash = createHash('sha256'), chunk = Buffer.alloc(65536); let remaining = component.bytes;
      try { onCreated?.(path, await output.stat({ bigint: true }));
        while (remaining) { const bytes = chunk.subarray(0, Math.min(chunk.length, remaining)); await exactly(opened.file, bytes, position); hash.update(bytes); await write(output, bytes); remaining -= bytes.length; position += bytes.length; }
        await output.sync(); if (hash.digest('hex') !== component.archiveSha256) throw failure();
      } finally { chunk.fill(0); await output.close(); }
      const inventory = await inspectVolumeArchive(path, component.role);
      if (inventory.archiveSha256 !== component.archiveSha256 || inventory.contentSha256 !== component.contentSha256) throw failure();
      archives[component.role] = path; inventories[component.role] = inventory;
    }
    if (position !== Number(opened.stat.size)) throw failure(); await unchanged(sourcePath, opened);
    return { metadata: header.metadata, archives, inventories };
  } catch { throw failure(); } finally { await opened?.file.close(); }
}
