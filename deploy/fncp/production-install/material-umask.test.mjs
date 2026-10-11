import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync, statSync, rmSync, realpathSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

test('fresh synthetic core material preserves exact recipient modes under umask077 and rejects rerun',()=>{
  const root=realpathSync(mkdtempSync(join(tmpdir(),'fncp-umask-test-')));chmodSync(root,0o700);
  try{
    const configuration={version:1,classification:'closed-local-core',deployment:'fncp-umask-test',platform:'linux/arm64',engine:{host:'unix:///unused/docker.sock',configDirectory:root},stateDirectory:root,sourceRevision:'a'.repeat(40),database:{name:'fncp_test',owner:'fncp_owner',migrationRole:'fncp_migrate',runtimeRole:'fncp_runtime',mathRole:'fncp_math',host:'postgres',port:5432},binding:{conversationId:'3syntheticTest',statementIds:Array.from({length:15},(_,n)=>n)},identity:{issuer:'https://issuer.invalid/',audience:'synthetic',jwksUri:'https://issuer.invalid/jwks'}};
    const path=join(root,'configuration.json');writeFileSync(path,JSON.stringify(configuration),{mode:0o600});
    const module=fileURLToPath(new URL('../selfhost/prepare-local-material.mjs',import.meta.url));
    const run=()=>spawnSync(process.execPath,['--input-type=module','-e','process.umask(0o077); const {prepareLocalMaterial}=await import(process.argv[2]); await prepareLocalMaterial(process.argv[3]);','synthetic-test',module,path],{encoding:'utf8',timeout:30000});
    const r=run();assert.equal(r.status,0,r.stderr);
    assert.equal(statSync(join(root,'material')).mode&0o777,0o700);
    for(const name of ['database-owner-password','database-migration-password','database-runtime-password','database-math-password','database-ca.pem','database-server.pem','database-server.key','jwt-private.pem','jwt-public.pem'])assert.equal(statSync(join(root,'material',name)).mode&0o777,0o644,name);
    for(const name of ['api.env','math.env','migration.env','local-ca.key'])assert.equal(statSync(join(root,'material',name)).mode&0o777,0o600,name);
    assert.notEqual(run().status,0);
  }finally{rmSync(root,{recursive:true,force:true});}
});
