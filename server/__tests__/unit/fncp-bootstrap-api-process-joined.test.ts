/** Joined real issuer/trust/bridge/Node-child/TLS tests. Only the final app is
 * a newly authored Express fixture; no actual Pol.is app, DB or retained dist
 * is imported. Private tokens and configuration stay inside the test parent.
 */
import { fork } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  unlinkSync,
  rmdirSync,
} from "node:fs";
import { join } from "node:path";
import ts from "typescript";

const serverRoot = join(__dirname, "../..");
const typescriptSources = [
  "src/bootstrap/child-owner.ts",
  "src/bootstrap/child-profile.ts",
  "src/bootstrap/https-entrypoint.ts",
  "src/bootstrap/https-runtime.ts",
  "src/auth/fncp-bootstrap-admission.ts",
  "src/auth/fncp-bootstrap-startup.ts",
  "src/auth/fncp-log-boundary.ts",
];
const moduleSources = [
  "bootstrap-issuer.mjs",
  "bootstrap-api-trust.mjs",
  "bootstrap-api-process.mjs",
];

const harnessSource = String.raw`"use strict";
const cp=require('node:child_process');
const {request}=require('node:https');
const {connect}=require('node:net');
const {pathToFileURL}=require('node:url');
const {join}=require('node:path');
const originalFork=cp.fork, children=[];let spawns=0;
// Transparent observation of real forks only; no fake owner or trust factory.
cp.fork=function(...args){const child=originalFork(...args);spawns++;
 const exited=new Promise(resolve=>child.once('exit',resolve));
 const disconnected=new Promise(resolve=>child.once('disconnect',resolve));
 children.push({child,done:Promise.all([exited,disconnected])});return child;};
let issuer,api,work,ending=false;
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function bounded(p,ms){let timer;try{return await Promise.race([p,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('joined test deadline')),ms);})]);}finally{clearTimeout(timer);}}
async function refused(origin){await new Promise((resolve,reject)=>{
 const socket=connect({host:'127.0.0.1',port:Number(new URL(origin).port)});
 socket.setTimeout(750);socket.once('connect',()=>{socket.destroy();reject(new Error('not refused'));});
 socket.once('timeout',()=>{socket.destroy();reject(new Error('refusal deadline'));});
 socket.once('error',e=>{socket.destroy();e.code==='ECONNREFUSED'?resolve():reject(new Error('refusal failed'));});});}
function environment(issuerOrigin){const n='a'.repeat(24),db='postgres://fncp_fresh_'+ 'b'.repeat(24)+':'+ 'c'.repeat(64)+'@fncp-fresh-pg-'+n+':5432/fncp_fresh_'+ 'd'.repeat(24);
 return {PATH:'/usr/bin:/bin',LANG:'C',LC_ALL:'C',FNCP_FRESH_BOOTSTRAP_LOCAL_ONLY:'true',NODE_ENV:'production',
 DEV_MODE:'false',TESTING:'false',ENABLE_TELEMETRY:'false',USE_NETWORK_HOST:'false',SHOULD_USE_TRANSLATION_API:'false',BACKFILL_COMMENT_LANG_DETECTION:'false',RUN_PERIODIC_EXPORT_TESTS:'false',SERVER_LOG_TO_FILE:'false',
 EMAIL_TRANSPORT_TYPES:'disabled',ADMIN_EMAILS:'[]',ADMIN_UIDS:'[]',API_SERVER_PORT:'5000',DATABASE_SSL:'true',
 AUTH_AUDIENCE:'fncp-fresh-synthetic-bootstrap',AUTH_ISSUER:issuerOrigin,
 FNCP_BOOTSTRAP_DATABASE_CERTIFICATE_SHA256:'e'.repeat(64),FNCP_BOOTSTRAP_JWKS_CERTIFICATE_SHA256:'f'.repeat(64),
 LOGIN_CODE_PEPPER:'1'.repeat(64),ENCRYPTION_PASSWORD_00001:'2'.repeat(64),DATABASE_URL:db,READ_ONLY_DATABASE_URL:db,
 JWKS_URI:'https://fncp-fresh-jwks-'+n+':8444/.well-known/jwks.json',API_PROD_HOSTNAME:'fncp-fresh-api-'+n+':8443',DOMAIN_OVERRIDE:'fncp-fresh-api-'+n+':8443',
 POLIS_JWT_ISSUER:'https://fncp-fresh-api-'+n+':8443/',POLIS_JWT_AUDIENCE:'fncp-fresh-synthetic-participants',
 JWT_PRIVATE_KEY_PATH:'/run/fncp/bootstrap/participant-private.pem',JWT_PUBLIC_KEY_PATH:'/run/fncp/bootstrap/participant-public.pem'};}
async function canonicalCreate(configuration,token){
 const body=JSON.stringify({topic:'FNCP Option C fresh disposable access QA',description:'Synthetic local test only. No genuine participant data.',
 is_active:true,is_anon:true,is_draft:false,is_data_open:false,topics_enabled:false,treevite_enabled:false,strict_moderation:true,profanity_filter:false,spam_filter:false});
 return bounded(new Promise((resolve,reject)=>{const req=request(configuration.origin+'/api/v3/conversations',{
 method:'POST',ca:configuration.certificatePem,rejectUnauthorized:true,agent:false,
 headers:{accept:'application/json','content-type':'application/json','x-forwarded-proto':'https',connection:'close',authorization:'Bearer '+token,'content-length':Buffer.byteLength(body)}},res=>{
 let text='';res.on('data',chunk=>{text+=chunk.toString();if(text.length>2048)res.destroy();});
 res.on('error',reject);res.on('end',()=>resolve({httpStatus:res.statusCode,syntheticResponseMatched:res.complete&&text==='{"conversation_id":"3JoinedSynthetic"}'}));});
 req.on('error',reject);req.setTimeout(2000,()=>req.destroy(new Error('request deadline')));req.end(body);}),3000);}
async function cleanup(){const results=await Promise.allSettled([Promise.resolve().then(()=>api?.close()),Promise.resolve().then(()=>issuer?.close())]);
 await bounded(Promise.all(children.map(x=>x.done)),5000);if(results.some(x=>x.status==='rejected'))throw new Error('joined cleanup failed');}
async function run(mode){const base=pathToFileURL(join(__dirname,'deploy/fncp/fresh-runtime/')).href;
 const {createBootstrapIssuer}=await import(base+'bootstrap-issuer.mjs');
 const {createBootstrapApiTrust}=await import(base+'bootstrap-api-trust.mjs');
 const {createBootstrapApiProcess}=await import(base+'bootstrap-api-process.mjs');
 issuer=await createBootstrapIssuer();const issuerOrigin=issuer.configuration().issuer;
 const trust=await createBootstrapApiTrust({issuer});
 if(mode==='closed-before-bridge'){
  await issuer.close();let rejected=false;try{api=await createBootstrapApiProcess({trust,environment:environment(issuerOrigin)});}catch{rejected=true;}
  await refused(issuerOrigin);await cleanup();return {mode,rejected,spawns,ready:false,issuerRefused:true,issuer:issuer.summary(),allChildrenExited:true};}
 api=await createBootstrapApiProcess({trust,environment:environment(issuerOrigin)});
 const configuration=api.configuration();const before=api.summary();
 // The original issuer mints the sole bearer. It never leaves this harness.
 const requestResult=await canonicalCreate(configuration,issuer.issueToken());
 if(mode==='issuer-close'){
  await issuer.close();
  await bounded((async()=>{for(;;){const s=api.summary();if(s.closed&&s.ownerClosureAcknowledged&&s.owner?.childExitVerified&&s.owner?.ipcDisconnected&&s.owner?.listenerClosureVerified)return;await delay(10);}})(),5000);
 }else await api.close();
 await refused(configuration.origin);let privateHandoffDenied=false;try{api.configuration();}catch{privateHandoffDenied=true;}
 const after=api.summary();await issuer.close();await refused(issuerOrigin);await cleanup();
 return {mode,...requestResult,spawns,ready:before.owner.ready,before,after,privateHandoffDenied,apiRefused:true,issuerRefused:true,issuer:issuer.summary(),allChildrenExited:true};}
process.once('message',m=>{if(m.type!=='run'||work)return;work=run(m.mode);work.then(async result=>{
 ending=true;process.send({type:'RESULT',result},()=>process.exit(0));},async()=>{ending=true;
 try{await cleanup();process.send({type:'FAILED'},()=>process.exit(1));}catch{process.exit(1);}});});
process.once('disconnect',()=>{if(!ending)void Promise.resolve(work).catch(()=>{}).then(cleanup).finally(()=>process.exit(1));});
process.once('SIGTERM',()=>{void issuer?.close();void Promise.resolve(work).catch(()=>{}).then(cleanup).finally(()=>process.exit(1));});
`;

function fixture() {
  const dir = mkdtempSync(join(serverRoot, ".fncp-api-process-joined-test-"));
  const directories = [
    "deploy",
    "deploy/fncp",
    "deploy/fncp/fresh-runtime",
    "server",
    "server/dist",
    "server/dist/src",
    "server/dist/src/bootstrap",
    "server/dist/src/auth",
  ];
  for (const path of directories) mkdirSync(join(dir, path), { mode: 0o700 });
  const written: string[] = [];
  function write(path: string, source: string) {
    writeFileSync(join(dir, path), source, { flag: "wx", mode: 0o600 });
    written.push(path);
  }
  for (const path of typescriptSources)
    write(
      "server/dist/" + path.replace(/\.ts$/, ".js"),
      ts.transpileModule(readFileSync(join(serverRoot, path), "utf8"), {
        compilerOptions: {
          module: ts.ModuleKind.CommonJS,
          target: ts.ScriptTarget.ES2022,
          esModuleInterop: true,
        },
      }).outputText
    );
  for (const name of moduleSources)
    write(
      "deploy/fncp/fresh-runtime/" + name,
      readFileSync(
        join(serverRoot, "../deploy/fncp/fresh-runtime", name),
        "utf8"
      )
    );
  write(
    "deploy/fncp/seed-statements.json",
    readFileSync(
      join(serverRoot, "../deploy/fncp/seed-statements.json"),
      "utf8"
    )
  );
  write(
    "server/dist/app.js",
    "const express=require('express');const app=express();app.use(express.json());app.use((_req,res)=>res.json({conversation_id:'3JoinedSynthetic'}));exports.default=app;exports.appReady=Promise.resolve();"
  );
  write("parent-harness.cjs", harnessSource);
  return {
    dir,
    remove() {
      for (const path of written) unlinkSync(join(dir, path));
      for (const path of [...directories].reverse()) rmdirSync(join(dir, path));
      rmdirSync(dir);
    },
  };
}

async function deadline<T>(promise: Promise<T>, ms = 12000): Promise<T> {
  let timer: NodeJS.Timeout;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error("joined synthetic parent deadline")),
          ms
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function joined(mode: string) {
  const f = fixture();
  const child = fork(join(f.dir, "parent-harness.cjs"), [], {
    cwd: f.dir,
    execPath: process.execPath,
    execArgv: [],
    env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
    stdio: ["ignore", "ignore", "ignore", "ipc"],
  });
  let result: any;
  child.on("message", (value: any) => {
    if (value.type === "RESULT") result = value.result;
  });
  const exited = new Promise<void>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", () => resolve());
  });
  const disconnected = new Promise<void>((resolve) =>
    child.once("disconnect", () => resolve())
  );
  const ended = Promise.all([exited, disconnected]).then(() => {});
  try {
    await new Promise<void>((resolve, reject) =>
      child.send({ type: "run", mode }, (error) =>
        error ? reject(error) : resolve()
      )
    );
    await deadline(ended);
    expect(child.exitCode).toBe(0);
    expect(result).toBeDefined();
    return result;
  } finally {
    if (child.exitCode === null && child.signalCode === null)
      child.kill("SIGTERM");
    await deadline(ended, 6000);
    // Only successful harness completion proves its descendant exit/readback.
    // Preserve fixtures on an uncertain failure instead of deleting live code.
    if (child.exitCode === 0 && result?.allChildrenExited) f.remove();
  }
}

test.each(["explicit-close", "issuer-close"])(
  "%s joins original issuer, branded public trust and real fixed API child with verified closure",
  async (mode) => {
    const result = await joined(mode);
    expect(result).toMatchObject({
      mode,
      httpStatus: 200,
      syntheticResponseMatched: true,
      spawns: 1,
      ready: true,
      apiRefused: true,
      issuerRefused: true,
      privateHandoffDenied: true,
      allChildrenExited: true,
    });
    expect(result.before).toMatchObject({
      classification: "ORIGINAL_ISSUER_BOUND_API_CHILD_BRIDGE",
      imported: true,
      ownerCreationAttempted: true,
      closed: false,
      tokensMintedByBridge: 0,
      databaseOwnershipVerified: false,
      containerOwnershipVerified: false,
      activationGranted: false,
    });
    expect(result.after).toMatchObject({
      closed: true,
      ownerClosureAcknowledged: true,
      activityWatchActive: false,
      owner: {
        spawnAttempted: true,
        closed: true,
        childExitVerified: true,
        ipcDisconnected: true,
        listenerClosureVerified: true,
        exitCode: 0,
        signalCode: null,
        databaseOwnershipVerified: false,
        activationGranted: false,
      },
    });
    expect(result.issuer).toMatchObject({
      closed: true,
      listenersClosed: true,
      tokensIssued: 1,
      clientFetches: 1,
      verifiedTlsFetches: 1,
      polisMiddlewareExecuted: false,
      bootstrapExecuted: false,
      productionReady: false,
    });
  }
);

test("closing the original issuer before the bridge prevents a real child spawn", async () => {
  const result = await joined("closed-before-bridge");
  expect(result).toMatchObject({
    rejected: true,
    spawns: 0,
    ready: false,
    issuerRefused: true,
    allChildrenExited: true,
    issuer: {
      closed: true,
      listenersClosed: true,
      tokensIssued: 0,
      clientFetches: 1,
      verifiedTlsFetches: 1,
    },
  });
});
