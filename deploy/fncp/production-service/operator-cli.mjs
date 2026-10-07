import {readFileSync} from 'node:fs';
import {requestProductionOperator} from './operator.mjs';
process.umask(0o077);
try{const [stateDirectory,command]=process.argv.slice(2);if(process.argv.length!==4)throw Error();let payload;if(['activate','invitation','invitation-for-registration'].includes(command)){const chunks=[];let size=0;for await(const b of process.stdin){size+=b.length;if(size>65536)throw Error();chunks.push(b);}payload=JSON.parse(Buffer.concat(chunks).toString('utf8'));}const result=await requestProductionOperator({stateDirectory,command,payload});process.stdout.write(JSON.stringify(result)+'\n');}catch{process.stderr.write('Private operator operation rejected.\n');process.exitCode=1;}
