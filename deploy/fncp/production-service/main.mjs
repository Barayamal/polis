import {createProductionService} from './service.mjs';
import {startProductionOperator} from './operator.mjs';
process.umask(0o077);
let service,operator,monitor,stopping=false;
async function shutdown(code=0){if(stopping)return;stopping=true;clearInterval(monitor);try{service?.operator.closeAdmission();}catch{}let failed=false;try{await operator?.close();}catch{failed=true;}try{await service?.close();}catch{failed=true;}process.exitCode=failed?1:code;}
process.once('SIGTERM',()=>void shutdown());process.once('SIGINT',()=>void shutdown());
process.once('uncaughtException',()=>void shutdown(1));process.once('unhandledRejection',()=>void shutdown(1));
try{
 if(process.argv.length!==3)throw Error();service=await createProductionService({configurationPath:process.argv[2]});if(stopping){await service.close();throw Error();}operator=await startProductionOperator(service);if(stopping){await operator.close();await service.close();throw Error();}const state=await service.start();if(stopping){await operator.close();await service.close();throw Error();}process.stdout.write(JSON.stringify({profile:state.profile,ready:true,roundOpen:false})+'\n');
 monitor=setInterval(()=>{try{service.operator.status();}catch{void shutdown(1);}},1000);monitor.unref();
}catch{process.stderr.write('Production service startup rejected.\n');await shutdown(1);}
