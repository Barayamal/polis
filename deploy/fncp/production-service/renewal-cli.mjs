import { pathToFileURL } from 'node:url';
import { renewClosedProductionCredentials } from './renewal.mjs';

export function runRenewalCli(args) {
  if (args.length !== 4 || args[0] !== '--source-manifest' || args[2] !== '--target-manifest'
    || !args[1] || !args[3]) throw new Error('Offline production credential renewal denied.');
  return renewClosedProductionCredentials({ sourceConfigurationPath: args[1], targetConfigurationPath: args[3] });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { process.stdout.write(JSON.stringify(runRenewalCli(process.argv.slice(2))) + '\n'); }
  catch { process.stderr.write('Offline production credential renewal denied. No launch is authorized.\n'); process.exitCode = 1; }
}
