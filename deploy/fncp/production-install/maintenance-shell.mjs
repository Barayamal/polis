/** This boundary accepts raw shell argv only. Normal Compose commands already
 * contain their own escapes and must never pass through it. Compose consumes
 * one dollar from each pair before the container shell evaluates its input. */
export function composeRawShellCommand(command) {
  if (!Array.isArray(command) || command.length !== 2 || !['-c','-euc'].includes(command[0])
    || typeof command[1] !== 'string' || !command[1] || command[1].includes('\0')) throw new Error('FNCP_MAINTENANCE_SHELL_REJECTED');
  // A replacement string '$$' means one literal dollar to String.replaceAll.
  // Use a function to preserve the two dollars required by Compose.
  return [command[0], command[1].replaceAll('$', () => '$$')];
}

export const MARIADB_FRESH_INITIALIZE = 'test -z "$(ls -A /var/lib/mysql)"; mariadb-install-db --no-defaults --datadir=/var/lib/mysql --auth-root-authentication-method=socket --auth-root-socket-user=root --skip-test-db >/tmp/initialize.log 2>&1';
