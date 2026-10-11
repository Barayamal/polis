import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { materialArchiveArguments } from './material-archive.mjs';

const run = (binary,args,input) => {
  const r=spawnSync(binary,args,{input,maxBuffer:1024*1024,timeout:10000});
  assert.equal(r.status,0,r.stderr?.toString()); return r.stdout;
};
test('material archive carries exact bytes without macOS AppleDouble entries', t => {
  const root=mkdtempSync(join(tmpdir(),'fncp-material-archive-'));t.after(()=>rmSync(root,{recursive:true}));
  const names=['config.json','server.pem','server-key.pem','upstream-ca.pem'];
  for(const name of names){writeFileSync(join(root,name),'invented '+name+'\n',{mode:0o600});
    if(process.platform==='darwin')run('xattr',['-w','com.barayamal.fncp.qa','invented metadata',join(root,name)]);}
  const archive=run('tar',materialArchiveArguments(root,names));
  assert.deepEqual(run('tar',['-tf','-'],archive).toString().trim().split('\n'),names);
  const out=join(root,'extracted');mkdirSync(out,{mode:0o700});run('tar',['-xf','-','-C',out],archive);
  for(const name of names)assert.equal(readFileSync(join(out,name),'utf8'),'invented '+name+'\n');
});
test('maintenance archive preserves nested scripts without host metadata files',t=>{
  const root=mkdtempSync(join(tmpdir(),'fncp-maintenance-archive-'));t.after(()=>rmSync(root,{recursive:true}));
  mkdirSync(join(root,'maintenance'));writeFileSync(join(root,'maintenance','owner.php'),'<?php /* invented */\n');
  if(process.platform==='darwin')run('xattr',['-w','com.barayamal.fncp.qa','invented metadata',join(root,'maintenance','owner.php')]);
  const names=run('tar',['-tf','-'],run('tar',materialArchiveArguments(root,['.']))).toString().trim().split('\n').sort();
  assert.deepEqual(names,['./','./maintenance/','./maintenance/owner.php']);
});
test('archive boundary refuses option injection, traversal and mixed whole-tree input',()=>{
  for(const names of [['--files-from=private'],['../private'],['file','file'],['.','file'],['a/b'],[]])assert.throws(()=>materialArchiveArguments('/tmp',names));
  assert.throws(()=>materialArchiveArguments('relative',['file']));
});
