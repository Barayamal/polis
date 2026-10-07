import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const original=readFileSync(new URL('../bin/run',import.meta.url),'utf8');
const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";
function fixture(fn) {
  const dir=mkdtempSync(join(tmpdir(),'fncp-math-launch-test-'));
  try {
    const log=join(dir,'java-args'),java=join(dir,'java'),classpath=join(dir,'classpath'),script=join(dir,'run');
    writeFileSync(classpath,'/synthetic/src:/synthetic/runtime.jar');
    writeFileSync(java,`#!/bin/sh\nprintf '%s\\n' "$$" "$@" > ${quote(log)}\nexit 37\n`,{mode:0o700});
    // Keep the branch/control flow verbatim. Replace only the two immutable
    // runtime locations with disposable test paths; no runtime injection knob.
    assert.equal(original.split('/opt/java/openjdk/bin/java').length-1,2);
    assert.equal(original.split('/app/classpath').length-1,2);
    writeFileSync(script,original.replaceAll('/opt/java/openjdk/bin/java',quote(java)).replaceAll('/app/classpath',quote(classpath)),{mode:0o700});
    fn({log,script});
  } finally {rmSync(dir,{recursive:true,force:true});}
}
test('dedicated launcher execs one 1024 MiB JVM and preserves its failure status',()=>fixture(({log,script})=>{
  const result=spawnSync('/bin/sh',[script],{env:{PATH:'/usr/bin:/bin',FNCP_OPTION_C_RELEASE_MODE:'production'},encoding:'utf8',timeout:3000});
  assert.equal(result.status,37);assert.equal(result.signal,null);
  const [pid,...args]=readFileSync(log,'utf8').trim().split('\n');
  assert.equal(Number(pid),result.pid,'exec must keep the container entry process PID');
  assert.deepEqual(args,['-Xmx1024m','-cp','/synthetic/src:/synthetic/runtime.jar','clojure.main','-m','polismath.runner','full']);
  assert.doesNotMatch(result.stdout,/REBOOTING|restarting/);
}));
test('present empty or invalid release mode exits before Java without falling into the upstream loop',()=>{
  for (const mode of ['', 'false','true','PRODUCTION']) fixture(({log,script})=>{
    const result=spawnSync('/bin/sh',[script],{env:{PATH:'/usr/bin:/bin',FNCP_OPTION_C_RELEASE_MODE:mode},encoding:'utf8',timeout:3000});
    assert.equal(result.status,1);assert.equal(result.signal,null);assert.equal(existsSync(log),false);
    assert.equal(result.stderr.trim(),'FNCP_MATH_RELEASE_MODE_INVALID');assert.doesNotMatch(result.stdout,/REBOOTING|restarting/);
  });
});
