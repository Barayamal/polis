<?php
declare(strict_types=1);
// Synthetic QA only, streamed to CLI in a network-none test container. Never
// included in the runtime image; emits aggregates, never credentials/cookies.
try {
    if (PHP_SAPI !== 'cli' || posix_geteuid() !== 33) { throw new RuntimeException(); }
    require '/opt/fncp-wordpress/material.php';
    $c = fncp_runtime_configuration();
    $owner = json_decode(file_get_contents('/run/fncp/wordpress-initialize/owner.json'), true, 8, JSON_THROW_ON_ERROR);
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $db = new mysqli('localhost', $c['databaseUser'], $c['databasePassword'], $c['databaseName'], 0, '/run/mysqld/mysqld.sock');
    $prefix = $c['tablePrefix'];
    $users = (int)$db->query("SELECT COUNT(*) AS n FROM {$prefix}users")->fetch_assoc()['n'];
    $admins = 0;
    foreach ($db->query("SELECT meta_value FROM {$prefix}usermeta WHERE meta_key='{$prefix}capabilities'") as $row) {
        $caps=unserialize($row['meta_value'],['allowed_classes'=>false]);
        if($caps===['administrator'=>true,'fncp_manage_registrations'=>true]) {$admins++;}
    }
    $options = [];
    foreach ($db->query("SELECT option_name,option_value FROM {$prefix}options WHERE option_name IN ('users_can_register','blog_public','active_plugins','siteurl','home','fncp_production_wordpress_v1')") as $row) { $options[$row['option_name']] = $row['option_value']; }
    if ($users !== 1 || $admins !== 1 || ($options['users_can_register'] ?? '') !== '0' || ($options['blog_public'] ?? '') !== '0'
        || ($options['active_plugins'] ?? '') !== 'a:0:{}' || ($options['siteurl'] ?? '') !== $c['wordpressOrigin'] || ($options['home'] ?? '') !== $c['wordpressOrigin']) { throw new RuntimeException('site'); }
    $grants = [];
    foreach ($db->query('SHOW GRANTS') as $row) { $grants[] = array_values($row)[0]; }
    $dmlOnly = count($grants) === 2 && count(array_filter($grants, static fn($s): bool => str_starts_with($s, 'GRANT SELECT, INSERT, UPDATE, DELETE ON '))) === 1;
    if (!$dmlOnly) { throw new RuntimeException('privileges'); }
    $state=json_decode($options['fncp_production_wordpress_v1']??'',true,16,JSON_THROW_ON_ERROR);
    $plugin=json_decode(fncp_runtime_read('plugin-config.json'),true,8,JSON_THROW_ON_ERROR);
    $expected=['schemaVersion'=>1,'configurationDigest'=>hash('sha256',FNCP_Production_Contract::canonical($plugin)),'lastObservedMs'=>0,'clockClosed'=>false,'registrations'=>[],'events'=>[]];
    if(FNCP_Production_Contract::canonical($state)!==FNCP_Production_Contract::canonical($expected)) {throw new RuntimeException('nonempty or unbound bridge');}
    $curl = curl_init();
    curl_setopt_array($curl, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_HEADER=>true, CURLOPT_FOLLOWLOCATION=>false,
        CURLOPT_SSL_VERIFYPEER=>true, CURLOPT_SSL_VERIFYHOST=>2, CURLOPT_CAINFO=>'/run/fncp/wordpress/receiver-ca.pem',
        CURLOPT_RESOLVE=>['wordpress:8443:127.0.0.1'], CURLOPT_PROXY=>'', CURLOPT_CONNECTTIMEOUT=>3, CURLOPT_TIMEOUT=>10,
        CURLOPT_COOKIEFILE=>'', CURLOPT_PROTOCOLS=>CURLPROTO_HTTPS]);
    $get = static function (string $path) use ($curl, $c): array {
        curl_setopt($curl, CURLOPT_URL, $c['wordpressOrigin'].$path); curl_setopt($curl, CURLOPT_HTTPGET, true);
        $body=curl_exec($curl); if ($body===false) { throw new RuntimeException('https'); }
        return [(int)curl_getinfo($curl,CURLINFO_RESPONSE_CODE),$body];
    };
    [$code,$body]=$get('/wp-login.php');
    if($code!==200 || !str_contains($body,'name="log"')) { throw new RuntimeException('login form'); }
    curl_setopt($curl, CURLOPT_POST, true);
    curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query(['log'=>$owner['operatorLogin'],'pwd'=>$owner['operatorPassword'],'wp-submit'=>'Log In','redirect_to'=>$c['wordpressOrigin'].'/wp-admin/','testcookie'=>'1']));
    $body=curl_exec($curl);
    if($body===false || curl_getinfo($curl,CURLINFO_RESPONSE_CODE)!==302) { throw new RuntimeException('login'); }
    // Dashboard's Quick Draft creates an auto-draft on a GET. Authenticate via
    // Profile instead so this installation proof does not create sample posts.
    [$code,$body]=$get('/wp-admin/profile.php');
    if($code!==200 || !str_contains($body,'Profile')) { throw new RuntimeException('admin'); }
    [$code,$body]=$get('/wp-admin/install.php');
    if(!in_array($code,[403,404],true)) { throw new RuntimeException('installer exposed'); }
    $postCount=(int)$db->query("SELECT COUNT(*) AS n FROM {$prefix}posts")->fetch_assoc()['n'];
    $commentCount=(int)$db->query("SELECT COUNT(*) AS n FROM {$prefix}comments")->fetch_assoc()['n'];
    if($postCount!==0 || $commentCount!==0) { throw new RuntimeException('sample content'); }
    $db->close(); curl_close($curl);
    echo json_encode(['pass'=>true,'users'=>$users,'administrators'=>$admins,'signupEnabled'=>false,'indexingEnabled'=>false,'activeOrdinaryPlugins'=>0,
        'samplePosts'=>$postCount,'sampleComments'=>$commentCount,'bridgeRegistrations'=>0,'bridgeEvents'=>0,'runtimeDmlOnly'=>$dmlOnly,'verifiedHttps'=>true,'syntheticStaffLogin'=>true,'installerBlocked'=>true,'participantRegistrationTested'=>false],JSON_THROW_ON_ERROR)."\n";
} catch(Throwable $e) { fwrite(STDERR,"Synthetic native WordPress probe rejected: ".$e->getMessage()."\n"); exit(1); }
