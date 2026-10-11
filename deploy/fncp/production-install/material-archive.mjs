import { isAbsolute, resolve } from 'node:path';

/** Only portable file bytes and ordinary tar metadata cross this boundary.
 * BSD tar's default pax format can add hidden AppleDouble files for host xattrs.
 * ustar excludes that extension; receiver-side exact entry checks still apply. */
export function materialArchiveArguments(directory, names) {
  if (typeof directory !== 'string' || !isAbsolute(directory) || resolve(directory) !== directory
    || !Array.isArray(names) || !names.length || new Set(names).size !== names.length
    || names.some(name => typeof name !== 'string' || !/^(?:\.|[A-Za-z0-9][A-Za-z0-9_.-]{0,90})$/u.test(name))
    || names.includes('.') && names.length !== 1) throw new Error('FNCP_MATERIAL_ARCHIVE_REJECTED');
  return ['--format=ustar', '-cf', '-', '-C', directory, ...names];
}
