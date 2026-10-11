<?php
declare(strict_types=1);
/** Test doubles exercise the plugin boundary, not a running WordPress installation. */
$directory=realpath(sys_get_temp_dir()).'/fncp-wp-plugin-test-'.bin2hex(random_bytes(12));mkdir($directory,0700);
define('ABSPATH',$directory.'/');define('FNCP_PRODUCTION_WORDPRESS_CONFIG_FILE',$directory.'/config.json');
$hooks=[];$routes=[];$capability=false;$nonce=false;$sent=[];$transportCalls=[];$transportResponse=null;$cacheDeletes=0;
function add_action($name,$callback):void{global$hooks;$hooks[$name]=$callback;}
function register_rest_route($namespace,$route,$args):void{global$routes;$routes[$namespace.$route]=$args;}
function is_ssl():bool{return ($_SERVER['HTTPS']??'')==='on';}
function current_user_can($cap):bool{global$capability;return $capability&&$cap==='fncp_manage_registrations';}
function check_admin_referer($action,$key):void{global$nonce;if(!$nonce||!in_array($action,['fncp_production_decide','fncp_production_retry'],true)||$key!=='_fncp_nonce'){throw new RuntimeException('nonce-denied');}}
function wp_cache_delete($key,$group):void{global$cacheDeletes;$cacheDeletes++;}
function add_option($name,$raw,$deprecated,$autoload):bool{global$wpdb;if($name!=='fncp_production_wordpress_v1'||$autoload!==false){throw new RuntimeException('option');}if($wpdb->raw!==null){return false;}$wpdb->raw=$raw;return true;}
function wp_remote_post($url,$args){global$transportCalls,$transportResponse;$transportCalls[]=[$url,$args];return $transportResponse??new WP_Error;}
function is_wp_error($v):bool{return $v instanceof WP_Error;}
function wp_remote_retrieve_response_code($v){return $v['response']['code'];}
function wp_remote_retrieve_body($v){return $v['body'];}
function wp_unslash($v){return $v;}
function nocache_headers():void{}
function wp_send_json($v,$status):never{throw new JsonResponse($v,$status);}
function wp_die($v,$title,$args):never{throw new JsonResponse(['denied'=>true],$args['response']);}
function esc_html($v){return htmlspecialchars((string)$v,ENT_QUOTES);}
function esc_attr($v){return esc_html($v);}
function esc_url($v){return esc_html($v);}
function admin_url($v){return 'https://wordpress.test/wp-admin/'.$v;}
function wp_nonce_field($action,$key):void{}
function submit_button(...$args):void{}
function add_management_page(...$args):void{}
class WP_Error{}
class JsonResponse extends RuntimeException{public function __construct(public array$value,public int$status){parent::__construct('response');}}
class WP_REST_Response{public function __construct(public array$data,public int$status,public array$headers){}}
class Request{public function __construct(public string$action,public string$raw,public array$headers,public string$method='POST',public array$query=[]){ }function get_method(){return$this->method;}function get_route(){return'/fncp/v1/'.$this->action;}function get_query_params(){return$this->query;}function get_header($n){return$this->headers[$n]??null;}function get_body(){return$this->raw;}}
class Database{public ?string$raw=null;public string$last_error='';public bool$broken=false;public array$sql=[];function prepare($sql,...$args){$this->sql[]=$sql;return[$sql,$args];}function get_var($q){$this->last_error=$this->broken?'SECRET_DATABASE_ERROR':'';return$this->raw;}function query($q){if($this->broken){return false;}[$sql,$args]=$q;if(!str_contains($sql,'BINARY option_value = %s')){throw new RuntimeException('binary-CAS');}[$next,$name,$old]=$args;if($old!==$this->raw){return 0;}$this->raw=$next;return 1;}public string$options='wp_options';}
$wpdb=new Database;
require_once __DIR__.'/fncp-production-wordpress.php';
function ensure(bool$ok):void{if(!$ok){throw new RuntimeException('Assertion failed.');}}
function rejected(callable$fn):void{try{$fn();}catch(Throwable$e){return;}throw new RuntimeException('Expected rejection.');}
function runAdmin(callable$fn):JsonResponse{try{$fn();}catch(JsonResponse$e){return$e;}throw new RuntimeException('No response.');}
function keystr(int$n):string{return rtrim(strtr(base64_encode(str_repeat(chr($n),32)),'+/','-_'),'=');}
$checks=[];function check(string$name,callable$fn):void{global$checks;$fn();$checks[]=$name;}
try {
    $_SERVER=['HTTPS'=>'on','HTTP_HOST'=>'wordpress.test','REQUEST_METHOD'=>'POST','HTTP_ORIGIN'=>'https://wordpress.test'];$_GET=[];$_FILES=[];
    check('unconfigured plugin stays closed with no storage transport or role assignment',function(){global$wpdb,$transportCalls,$hooks;rejected(fn()=>fncp_production_configuration());ensure($wpdb->raw===null&&$transportCalls===[]);ensure(!isset($hooks['admin_post_nopriv_fncp_production_decide'])&&!isset($hooks['wp_mail'])&&!isset($hooks['init']));});
    $key=openssl_pkey_new(['private_key_bits'=>2048,'private_key_type'=>OPENSSL_KEYTYPE_RSA]);$csr=openssl_csr_new(['commonName'=>'Fixture CA'],$key,['digest_alg'=>'sha256']);$cert=openssl_csr_sign($csr,null,$key,1,['digest_alg'=>'sha256']);openssl_x509_export($cert,$pem);file_put_contents($directory.'/ca.pem',$pem);chmod($directory.'/ca.pem',0400);
    $c=['profile'=>FNCP_Production_Contract::PROFILE,'deploymentId'=>'test_deployment','conversationId'=>'test_round','wordpressOrigin'=>'https://wordpress.test','eventEndpoint'=>'https://participant.test/internal/wordpress/events','consentVersion'=>'reviewed-v1','noticeSha256'=>str_repeat('a',64),'serviceRequestKey'=>keystr(1),'serviceResponseKey'=>keystr(2),'eventKey'=>keystr(3),'caFile'=>$directory.'/ca.pem'];
    file_put_contents(FNCP_PRODUCTION_WORDPRESS_CONFIG_FILE,json_encode($c));chmod(FNCP_PRODUCTION_WORDPRESS_CONFIG_FILE,0600);
    check('private config and certificate are accepted without network',function()use($c){ensure(fncp_production_configuration()===$c);});
    check('world-readable config, symlink config and missing trust material reject',function()use($directory){chmod(FNCP_PRODUCTION_WORDPRESS_CONFIG_FILE,0644);clearstatcache();rejected(fn()=>fncp_production_configuration());chmod(FNCP_PRODUCTION_WORDPRESS_CONFIG_FILE,0600);rename(FNCP_PRODUCTION_WORDPRESS_CONFIG_FILE,$directory.'/config.saved');symlink($directory.'/config.saved',FNCP_PRODUCTION_WORDPRESS_CONFIG_FILE);clearstatcache();rejected(fn()=>fncp_production_configuration());unlink(FNCP_PRODUCTION_WORDPRESS_CONFIG_FILE);rename($directory.'/config.saved',FNCP_PRODUCTION_WORDPRESS_CONFIG_FILE);rename($directory.'/ca.pem',$directory.'/ca.saved');clearstatcache();rejected(fn()=>fncp_production_configuration());rename($directory.'/ca.saved',$directory.'/ca.pem');clearstatcache();});
    $now=time();$body=['schemaVersion'=>1,'deploymentId'=>'test_deployment','conversationId'=>'test_round','receiptId'=>FNCP_Production_Contract::uuid4(),'accountId'=>'acct_'.str_repeat('A',43),'consentVersion'=>'reviewed-v1','noticeSha256'=>str_repeat('a',64),'adultSelfAttested'=>true,'eligibilitySelfAttested'=>true,'registrationConsent'=>true,'issuedAt'=>$now,'expiresAt'=>$now+60];$raw=FNCP_Production_Contract::canonical($body);
    $headers=['content-type'=>'application/json','x-fncp-timestamp'=>(string)$now,'x-fncp-signature'=>'sha256='.FNCP_Production_Contract::mac(FNCP_Production_Contract::REQUEST_DOMAIN."register\n".$now.'.'.$raw,$c['serviceRequestKey'])];
    check('REST registers only expectedPOSTroutes and absent optional headers are null',function()use($raw,$headers){global$hooks,$routes;$hooks['rest_api_init']();ensure(array_keys($routes)===['fncp/v1/register','fncp/v1/status']);$r=fncp_production_rpc(new Request('register',$raw,$headers),'register');ensure($r->status===200&&isset($r->data['payload'],$r->data['signature'])&&$r->headers['Cache-Control']==='no-store, private');});
    $registrationId=fncp_production_store($c)->adminRows()[0]['registrationId'];
    check('wronghost forgedforwardedTLS browsercookies origin and query are rejected',function()use($raw,$headers){foreach(['cookie'=>'x=y','origin'=>'https://wordpress.test','sec-fetch-site'=>'same-origin','authorization'=>'sentinel']as$k=>$v){$h=$headers;$h[$k]=$v;ensure(fncp_production_rpc(new Request('register',$raw,$h),'register')->status===503);}ensure(fncp_production_rpc(new Request('register',$raw,$headers,'POST',['extra'=>'1']),'register')->status===503);$_SERVER['HTTP_HOST']='evil.test';ensure(fncp_production_rpc(new Request('register',$raw,$headers),'register')->status===503);$_SERVER['HTTP_HOST']='wordpress.test';$_SERVER['HTTPS']='off';$_SERVER['HTTP_X_FORWARDED_PROTO']='https';ensure(fncp_production_rpc(new Request('register',$raw,$headers),'register')->status===503);$_SERVER['HTTPS']='on';unset($_SERVER['HTTP_X_FORWARDED_PROTO']);});
    $_POST=['action'=>'fncp_production_decide','_fncp_nonce'=>'fixture','registration_id'=>$registrationId,'state'=>'approved'];
    check('operator capability and nonce are independently mandatory',function(){global$capability,$nonce,$transportCalls;$capability=false;$nonce=true;ensure(runAdmin('fncp_production_decide')->status===503);$capability=true;$nonce=false;ensure(runAdmin('fncp_production_decide')->status===503);ensure($transportCalls===[]);$nonce=true;});
    check('operator resolves only registeredreference and no account override',function(){$_POST['accountId']='acct_'.str_repeat('B',43);ensure(runAdmin('fncp_production_decide')->status===503);unset($_POST['accountId']);$old=$_POST['registration_id'];$_POST['registration_id']=FNCP_Production_Contract::uuid4();ensure(runAdmin('fncp_production_decide')->status===503);$_POST['registration_id']=$old;});
    check('decision persists before native WP transport and usesTLS bounded exact endpoint',function()use($c){global$transportCalls,$wpdb;$r=runAdmin('fncp_production_decide');ensure($r->status===200&&$r->value===['outcome'=>'PENDING']);ensure(count(json_decode($wpdb->raw,true)['events'])===1);[$url,$a]=$transportCalls[0];ensure($url===$c['eventEndpoint']&&$a['sslverify']===true&&$a['sslcertificates']===$c['caFile']&&$a['redirection']===0&&$a['timeout']===3&&$a['limit_response_size']===4096&&$a['cookies']===[]&&!$a['stream']);ensure($a['body']===FNCP_Production_Contract::canonical(json_decode($a['body'],true)));});
    check('exactACK accepted and late failures cannot downgrade; public page excludes account',function()use($c){global$transportResponse,$transportCalls;$e=json_decode($transportCalls[0][1]['body'],true);$transportResponse=['response'=>['code'=>200],'body'=>json_encode(['ok'=>true,'eventId'=>$e['eventId'],'version'=>1])];$_POST=['action'=>'fncp_production_retry','_fncp_nonce'=>'fixture'];ensure(runAdmin('fncp_production_retry')->value===['outcome'=>'ACKNOWLEDGED']);ob_start();fncp_production_page();$html=ob_get_clean();ensure(!str_contains($html,'acct_')&&!str_contains($html,$c['serviceRequestKey'])&&str_contains($html,'approved'));});
    check('database diagnostics are never returned and failed store denies service',function()use($raw,$headers){global$wpdb;$wpdb->broken=true;$r=fncp_production_rpc(new Request('register',$raw,$headers),'register');ensure($r->status===503&&$r->data===['error'=>'registration_unavailable']);$wpdb->broken=false;});
    check('authenticated stale request reaches durable clock closure before freshness rejection',function()use($raw,$headers,$c){global$wpdb;$s=json_decode($wpdb->raw,true);$s['lastObservedMs']+=60000;$wpdb->raw=FNCP_Production_Contract::canonical($s);$h=$headers;$stamp=(string)(time()+60);$h['x-fncp-timestamp']=$stamp;$h['x-fncp-signature']='sha256='.FNCP_Production_Contract::mac(FNCP_Production_Contract::REQUEST_DOMAIN."register\n".$stamp.'.'.$raw,$c['serviceRequestKey']);ensure(fncp_production_rpc(new Request('register',$raw,$h),'register')->status===503);ensure(json_decode($wpdb->raw,true)['clockClosed']===true);});
    echo json_encode(['result'=>'PASS','tests'=>count($checks),'classification'=>'WORDPRESS_API_TEST_DOUBLES_NOT_ACTUAL_RUNTIME','checks'=>$checks],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)."\n";
} finally { foreach(['config.json','config.saved','ca.pem','ca.saved']as$n){if(file_exists($directory.'/'.$n)||is_link($directory.'/'.$n)){unlink($directory.'/'.$n);}}rmdir($directory); }
