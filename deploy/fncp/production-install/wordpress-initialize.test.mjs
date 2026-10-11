import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {randomBytes,createHash} from 'node:crypto';
const library=new URL('./wordpress-initialize-lib.php',import.meta.url).pathname;
const contract=new URL('../production-wordpress/contract.php',import.meta.url).pathname;
const entry=new URL('./wordpress-initialize.php',import.meta.url).pathname;
const canonical=v=>JSON.stringify(v, (k,x)=>x && typeof x==='object' && !Array.isArray(x) ? Object.fromEntries(Object.entries(x).sort(([a],[b])=>a.localeCompare(b))) : x);
const hash=v=>createHash('sha256').update(canonical(v)).digest('hex');
const token=()=>randomBytes(32).toString('base64url');
function fixture(){
  const c={profile:'FNCP_WORDPRESS_RUNTIME_V1',wordpressOrigin:'https://wordpress:8443',databaseName:'fncp_wordpress',databaseUser:'fncp_wp',databasePassword:token(),tablePrefix:'fncp_',salts:Array.from({length:8},token)};
  const plugin={profile:'FNCP_PRODUCTION_WORDPRESS_V1',deploymentId:'fncp-synthetic',conversationId:'8Synthetic',wordpressOrigin:c.wordpressOrigin,eventEndpoint:'https://participant-events:8444/internal/wordpress/events',consentVersion:'synthetic-v1',noticeSha256:'a'.repeat(64),serviceRequestKey:token(),serviceResponseKey:token(),eventKey:token(),caFile:'/run/fncp/wordpress/receiver-ca.pem'};
  const owner={profile:'FNCP_WORDPRESS_INITIALIZE_V1',siteTitle:'Community Pulse — invented installation',operatorLogin:'synthetic_operator',operatorEmail:'operator@example.test',operatorPassword:token()};
  const receipt={profile:'FNCP_WORDPRESS_INITIALIZED_V1',configurationDigest:hash(c),pluginDigest:hash(plugin),ownerDigest:hash(owner),operatorCount:1,registrationCount:0,eventCount:0,mailSent:false,participationOpened:false};
  const snapshot={options:{siteurl:c.wordpressOrigin,home:c.wordpressOrigin,db_version:'61200',active_plugins:'a:0:{}',blog_public:'0',users_can_register:'0',default_comment_status:'closed',default_ping_status:'closed',permalink_structure:'/%postname%/',fncp_fresh_install_v1:canonical(receipt)},users:[{login:owner.operatorLogin,email:owner.operatorEmail,capabilities:{administrator:true,fncp_manage_registrations:true}}],bridge:canonical({schemaVersion:1,configurationDigest:hash(plugin),lastObservedMs:0,clockClosed:false,registrations:[],events:[]})};
  return {c,plugin,owner,snapshot};
}
function run(x,operation='config'){
  const code=`require $argv[1]; require $argv[2]; $x=json_decode(stream_get_contents(STDIN),true,16,JSON_THROW_ON_ERROR); try {
    if($argv[3]==='config') fncp_initialize_configuration($x['c'],$x['plugin'],$x['owner']);
    elseif($argv[3]==='snapshot') fncp_initialize_assert_snapshot($x['snapshot'],$x['c'],$x['plugin'],$x['owner'],'61200');
    elseif($argv[3]==='json') fncp_initialize_json($x['raw']);
    elseif($argv[3]==='rewrites') fncp_initialize_assert_rewrites($x['raw']);
    elseif($argv[3]==='private') fncp_initialize_private_read($x['parent'],$x['name']);
    else exit(2); echo 'PASS';
  }catch(Throwable $e){fwrite(STDERR,'REJECT');exit(1);}`;
  const r=spawnSync('php',['-r',code,contract,library,operation],{input:JSON.stringify(x),encoding:'utf8',timeout:10000});
  assert.ok([0,1].includes(r.status),r.stderr); return r;
}
test('PHP maintenance source parses without loading WordPress or connecting to MariaDB',()=>{
  for(const path of [library,entry]) { const r=spawnSync('php',['-l',path],{encoding:'utf8'});assert.equal(r.status,0,r.stderr); }
});
test('accepts exact synthetic initialization and empty closed post-install snapshot',()=>{
  const f=fixture(); assert.equal(run(f).status,0);assert.equal(run(f,'snapshot').status,0);
});
test('canonical input requires exact newline and rejects duplicate/extra JSON representations',()=>{
  assert.equal(run({raw:'{"a":1}\n'},'json').status,0);
  for(const raw of ['{"a":1}','{"a":1,"a":1}\n','{ "a":1}\n','[1]\n','null\n']) {
    assert.equal(run({raw},'json').status,1);
  }
});
for(const [name,edit] of [
  ['unknown owner field',f=>{f.owner.extra=true;}],
  ['unknown database field',f=>{f.c.extra=true;}],
  ['wrong initialization profile',f=>{f.owner.profile='FNCP_LOCAL_ONLY';}],
  ['SQL database identifier',f=>{f.c.databaseName='test`;DROP DATABASE test;';}],
  ['SQL user identifier',f=>{f.c.databaseUser="test'@'%'";}],
  ['SQL table prefix',f=>{f.c.tablePrefix='wp_;';}],
  ['noncanonical owner password',f=>{f.owner.operatorPassword='x'.repeat(43);}],
  ['weak owner password',f=>{f.owner.operatorPassword='short';}],
  ['reused owner password',f=>{f.owner.operatorPassword=f.c.databasePassword;}],
  ['reused salt',f=>{f.c.salts[1]=f.c.salts[0];}],
  ['bridge key collides with salt',f=>{f.plugin.eventKey=f.c.salts[0];}],
  ['mismatched WordPress origin',f=>{f.plugin.wordpressOrigin='https://another.invalid';}],
  ['changed receiver trust path',f=>{f.plugin.caFile='/tmp/weak.pem';}],
  ['uppercase or sanitized operator identity',f=>{f.owner.operatorLogin='Owner User';}],
  ['email header injection',f=>{f.owner.operatorEmail='owner@example.test\r\nBcc: bad@example.test';}],
  ['title HTML',f=>{f.owner.siteTitle='<b>Title</b>';}],
  ['title control character',f=>{f.owner.siteTitle='Title\nUnexpected';}],
]) test(`rejects ${name} without outputting supplied private values`,()=>{
  const f=fixture();edit(f);const r=run(f);assert.equal(r.status,1);assert.equal(r.stdout,'');assert.equal(r.stderr,'REJECT');
});
for(const [name,edit] of [
  ['additional operator',f=>{f.snapshot.users.push(f.snapshot.users[0]);}],
  ['missing operator',f=>{f.snapshot.users=[];}],
  ['different operator email',f=>{f.snapshot.users[0].email='other@example.test';}],
  ['missing registration capability',f=>{delete f.snapshot.users[0].capabilities.fncp_manage_registrations;}],
  ['extra capability',f=>{f.snapshot.users[0].capabilities.unreviewed=true;}],
  ['public indexing',f=>{f.snapshot.options.blog_public='1';}],
  ['self registration',f=>{f.snapshot.options.users_can_register='1';}],
  ['active plugin',f=>{f.snapshot.options.active_plugins='a:1:{i:0;s:9:"other.php";}';}],
  ['changed origin',f=>{f.snapshot.options.home='https://wrong.invalid';}],
  ['plain permalink routing',f=>{f.snapshot.options.permalink_structure='';}],
  ['changed permalink routing',f=>{f.snapshot.options.permalink_structure='/%year%/';}],
  ['version mismatch',f=>{f.snapshot.options.db_version='1';}],
  ['stale receipt after credential change',f=>{f.owner.operatorPassword=token();}],
  ['existing registration',f=>{const s=JSON.parse(f.snapshot.bridge);s.registrations=[{}];f.snapshot.bridge=canonical(s);}],
  ['existing event',f=>{const s=JSON.parse(f.snapshot.bridge);s.events=[{}];f.snapshot.bridge=canonical(s);}],
  ['used or rolled-back bridge clock',f=>{const s=JSON.parse(f.snapshot.bridge);s.lastObservedMs=1;f.snapshot.bridge=canonical(s);}],
]) test(`post-install verification rejects ${name}`,()=>{const f=fixture();edit(f);assert.equal(run(f,'snapshot').status,1);});
test('private material reader cannot be redirected to another path or file',()=>{
  for(const [parent,name] of [['/tmp','owner.json'],['/run/fncp/wordpress-initialize','../config.json'],['/run/fncp/wordpress','server-key.pem']]) assert.equal(run({parent,name},'private').status,1);
});
test('CLI rejects absent/unknown phases before any material or database access',()=>{
  for(const args of [[],['unknown'],['site','extra']]){const r=spawnSync('php',[entry,...args],{encoding:'utf8'});assert.equal(r.status,1);assert.equal(r.stdout,'');assert.match(r.stderr,/initialization rejected/);}
});
test('maintenance stays absent from normal immutable image; no password arguments or HTTP mode',()=>{
  const dockerfile=readFileSync(new URL('../production-deployment/Dockerfile.wordpress',import.meta.url),'utf8');
  assert.doesNotMatch(dockerfile,/wordpress-initialize|production-install/);
  const source=readFileSync(entry,'utf8');assert.match(source,/PHP_SAPI !== 'cli'/);assert.match(source,/function wp_mail/);assert.match(source,/WP_HTTP_BLOCK_EXTERNAL/);
  assert.match(source,/TABLES WHERE TABLE_SCHEMA/);assert.match(source,/REVOKE CREATE,ALTER,DROP,INDEX/);
});
test('actual maintenance snapshot survives common bootstrap variable overwrite/unset',()=>{
  const source=readFileSync(entry,'utf8');
  const capture=source.indexOf('$fncpInitializerScope = compact(');
  const end='unset($fncpInitializerScope,$fncpInitializerName,$fncpInitializerValue);';
  const finish=source.indexOf(end,capture);
  assert.ok(capture>=0 && finish>capture);
  let fragment=source.slice(capture,finish+end.length);
  const includes="require '/usr/src/wordpress/wp-load.php'; require_once ABSPATH . 'wp-admin/includes/upgrade.php';";
  assert.equal(fragment.split(includes).length,2);
  // Execute the actual candidate capture/restore code while emulating core's
  // include-scope cleanup. This is not a substitute for the native rehearsal.
  fragment=fragment.replace(includes,"unset($c,$plugin,$owner,$configurationRaw,$pluginRaw,$ownerRaw,$phase,$db,$name,$user,$prefix,$assertMaterials); $c='overwritten'; $plugin='overwritten';");
  const code=`$c=['synthetic'=>'configuration'];$plugin=['synthetic'=>'plugin'];$owner=['synthetic'=>'owner'];
    $configurationRaw='config';$pluginRaw='plugin';$ownerRaw='owner';$phase='site';$db=new stdClass();$name='database';$user='account';$prefix='fncp_';$assertMaterials=static fn()=>true;
    $expected=compact('c','plugin','owner','configurationRaw','pluginRaw','ownerRaw','phase','db','name','user','prefix','assertMaterials');
    ${fragment}
    if($expected!==compact('c','plugin','owner','configurationRaw','pluginRaw','ownerRaw','phase','db','name','user','prefix','assertMaterials'))exit(1);echo 'PASS';`;
  const r=spawnSync('php',['-r',code],{encoding:'utf8',timeout:5000});assert.equal(r.status,0,r.stderr);assert.equal(r.stdout,'PASS');
});

function rewriteBytes(rules) {
  const r=spawnSync('php',['-r', '$x=json_decode(stream_get_contents(STDIN),true,8,JSON_THROW_ON_ERROR);echo serialize($x);'],{input:JSON.stringify(rules),encoding:'utf8'});
  assert.equal(r.status,0,r.stderr);return r.stdout;
}
test('persisted WordPress rewrites require both exact REST routes while retaining other core rules',()=>{
  const routes={'^wp-json/?$':'index.php?rest_route=/','^wp-json/(.*)?':'index.php?rest_route=/$matches[1]','robots\\.txt$':'index.php?robots=1'};
  assert.equal(run({raw:rewriteBytes(routes)},'rewrites').status,0);
  for(const raw of ['',rewriteBytes({}),rewriteBytes({...routes,'^wp-json/?$':'index.php'}),rewriteBytes({...routes,'^wp-json/(.*)?':'index.php?unreviewed=$matches[1]'}),rewriteBytes({...routes,extra:[]}),rewriteBytes(routes)+'trailing','O:8:"stdClass":0:{}']){
    assert.equal(run({raw},'rewrites').status,1);
  }
  const missing={...routes};delete missing['^wp-json/(.*)?'];assert.equal(run({raw:rewriteBytes(missing)},'rewrites').status,1);
});
test('actual initialization sets permalink state and registers REST routes before a database-only flush',()=>{
  const source=readFileSync(entry,'utf8');const start=source.indexOf("$wp_rewrite->set_permalink_structure('/%postname%/');");
  const finish=source.indexOf('flush_rewrite_rules(false);',start);assert.ok(start>0&&finish>start);
  const fragment=source.slice(start,finish+'flush_rewrite_rules(false);'.length);
  const code=`$calls=[];$wp_rewrite=new class {function set_permalink_structure($value){global $calls;$calls[]=['permalink',$value];}};
    function rest_api_register_rewrites(){global $calls;$calls[]=['rest'];}
    function flush_rewrite_rules($hard){global $calls;$calls[]=['flush',$hard];}
    ${fragment}
    if($calls!==[['permalink','/%postname%/'],['rest'],['flush',false]])exit(1);echo 'PASS';`;
  const r=spawnSync('php',['-r',code],{encoding:'utf8',timeout:5000});assert.equal(r.status,0,r.stderr);assert.equal(r.stdout,'PASS');
});
