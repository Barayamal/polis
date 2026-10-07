import { spawn } from 'node:child_process';
import { constants, createReadStream, createWriteStream } from 'node:fs';
import { open } from 'node:fs/promises';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { recoveryFailure } from './archive.mjs';

const CLEAN_ENV = { PATH: process.env.PATH, HOME: process.env.HOME, LANG: 'C', LC_ALL: 'C', DOCKER_CLI_HINTS: 'false' };

/** No shell, private bounded streams and fixed generic failures. Commands whose
 * diagnostics imply corruption opt into rejectStderr: any stderr byte rejects,
 * including warning-only exit 0. Diagnostic contents are never returned/logged.
 */
export async function runPrivateCommand(binary, args, { inputPath, outputPath, onOutputCreated,
  rejectStderr = false, limit = 2 * 1024 * 1024, timeout = 120_000 } = {}) {
  let outputFile;
  try {
    if (outputPath) {
      outputFile = await open(outputPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
      onOutputCreated?.(outputPath, await outputFile.stat({ bigint: true }));
    }
    const child = spawn(binary, args, { shell: false, env: CLEAN_ENV, stdio: ['pipe', 'pipe', 'pipe'] });
    let overflow = false; let stderrBytes = 0; let size = 0; const chunks = [];
    const timer = setTimeout(() => { overflow = true; child.kill('SIGKILL'); }, timeout);
    const exit = new Promise((resolveExit, reject) => {
      child.once('error', () => reject(recoveryFailure()));
      child.once('close', (code, signal) => (code === 0 && !signal && !overflow && !(rejectStderr && stderrBytes))
        ? resolveExit() : reject(recoveryFailure()));
    });
    child.stderr.on('data', bytes => { stderrBytes += bytes.length; if (stderrBytes > 65_536) { overflow = true; child.kill('SIGKILL'); } });
    const output = outputFile
      ? pipeline(child.stdout, new Transform({ transform(chunk, encoding, done) {
        size += chunk.length; if (size > limit) { overflow = true; child.kill('SIGKILL'); done(recoveryFailure()); } else done(null, chunk);
      } }), createWriteStream(outputPath, { fd: outputFile.fd, autoClose: false }))
      : new Promise((resolveOutput, reject) => {
        child.stdout.on('data', bytes => { size += bytes.length; if (size > limit) { overflow = true; child.kill('SIGKILL'); reject(recoveryFailure()); } else chunks.push(bytes); });
        child.stdout.on('end', resolveOutput); child.stdout.on('error', () => reject(recoveryFailure()));
      });
    let input;
    if (inputPath) input = pipeline(createReadStream(inputPath, { flags: constants.O_RDONLY | constants.O_NOFOLLOW }), child.stdin);
    else { child.stdin.on('error', () => {}); child.stdin.end(); input = Promise.resolve(); }
    try { await Promise.all([exit, input, output]); await outputFile?.sync(); return outputPath ? { bytes: size } : Buffer.concat(chunks).toString('utf8').trim(); }
    catch { child.kill('SIGKILL'); await Promise.allSettled([exit, input, output]); throw recoveryFailure(); }
    finally { clearTimeout(timer); }
  } catch { throw recoveryFailure(); }
  finally { await outputFile?.close(); }
}
