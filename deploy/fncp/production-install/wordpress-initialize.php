<?php
declare(strict_types=1);
/** Explicit maintenance entrypoint. This file is NOT copied into the normal image. */
ini_set('display_errors','0'); ini_set('log_errors','0'); ob_start();
require_once __DIR__ . '/wordpress-initialize-lib.php';
$fncpInitializationStage = 'ENTRY';
try {
    if (PHP_SAPI !== 'cli' || $argc !== 2 || !in_array($argv[1], ['database','site','finalize'], true) || !function_exists('posix_geteuid')
        || posix_geteuid() !== ($argv[1] === 'site' ? 33 : 0)) { fncp_initialize_deny(); }
    $phase = $argv[1]; umask(0077);
    $fncpInitializationStage = 'INPUT_VALIDATION';
    require_once '/usr/src/wordpress/wp-content/mu-plugins/fncp-production/contract.php';
    $configurationRaw = fncp_initialize_private_read('/run/fncp/wordpress','config.json');
    $pluginRaw = fncp_initialize_private_read('/run/fncp/wordpress','plugin-config.json');
    $ownerRaw = fncp_initialize_private_read('/run/fncp/wordpress-initialize','owner.json');
    $c = fncp_initialize_json($configurationRaw); $plugin = fncp_initialize_json($pluginRaw); $owner = fncp_initialize_json($ownerRaw);
    fncp_initialize_configuration($c,$plugin,$owner);
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $fncpInitializationStage = 'DATABASE_CONNECT';
    $db = mysqli_init(); $db->options(MYSQLI_OPT_CONNECT_TIMEOUT,5);
    $db->real_connect('localhost', $phase === 'site' ? $c['databaseUser'] : 'root', $phase === 'site' ? $c['databasePassword'] : '',
        $phase === 'database' ? null : $c['databaseName'], 0, '/run/mysqld/mysqld.sock');
    $db->set_charset('utf8mb4'); $db->query('SET SESSION MAX_STATEMENT_TIME=5');
    if ((string)$db->query("SELECT GET_LOCK('fncp_wordpress_initialize_v1',0) AS acquired")->fetch_assoc()['acquired'] !== '1') { fncp_initialize_deny(); }
    $name = $c['databaseName']; $user = $c['databaseUser']; $prefix = $c['tablePrefix'];
    $assertMaterials = static function () use ($configurationRaw,$pluginRaw,$ownerRaw): void {
        if (fncp_initialize_private_read('/run/fncp/wordpress','config.json') !== $configurationRaw
            || fncp_initialize_private_read('/run/fncp/wordpress','plugin-config.json') !== $pluginRaw
            || fncp_initialize_private_read('/run/fncp/wordpress-initialize','owner.json') !== $ownerRaw) { fncp_initialize_deny(); }
    };
    if ($phase === 'database') {
        $fncpInitializationStage = 'DATABASE_PRISTINE_CHECK';
        // Whole instance must be disposable and pristine. Never create beside another project.
        if ((int)$db->query("SELECT COUNT(*) AS n FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('mysql','information_schema','performance_schema','sys')")->fetch_assoc()['n'] !== 0
            || (int)$db->query("SELECT COUNT(*) AS n FROM mysql.user WHERE User='" . $db->real_escape_string($user) . "'")->fetch_assoc()['n'] !== 0) { fncp_initialize_deny(); }
        $assertMaterials();
        $fncpInitializationStage = 'DATABASE_CREATE';
        $db->query("CREATE DATABASE `$name` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
        $db->query("CREATE USER '$user'@'localhost' IDENTIFIED BY '" . $db->real_escape_string($c['databasePassword']) . "'");
        $db->query("GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,ALTER,DROP,INDEX ON `$name`.* TO '$user'@'localhost'");
        $result = ['result'=>'DATABASE_CREATED','operatorCount'=>0,'registrationCount'=>0,'mailSent'=>false,'participationOpened'=>false];
    } else {
        if ($phase === 'site') {
            $fncpInitializationStage = 'SITE_PRISTINE_CHECK';
            // No install/upgrade/retry is attempted when even one table exists.
            if ((int)$db->query("SELECT COUNT(*) AS n FROM information_schema.TABLES WHERE TABLE_SCHEMA='" . $db->real_escape_string($name) . "'")->fetch_assoc()['n'] !== 0) { fncp_initialize_deny(); }
            require_once '/opt/fncp-wordpress/material.php';
            $fncpInitializationStage = 'SITE_RUNTIME_MATERIAL';
            if (fncp_runtime_configuration() !== $c) { fncp_initialize_deny(); }
            fncp_runtime_validate_leaf(fncp_runtime_read('server.pem'), fncp_runtime_read('server-key.pem'), $c['wordpressOrigin'], time());
            $assertMaterials();
            // Block notifications before loading any WordPress/plugin bootstrap code.
            function wp_mail($to,$subject,$message,$headers='',$attachments=[],$embeds=[]) { return false; }
            define('WP_INSTALLING',true); define('WP_HTTP_BLOCK_EXTERNAL',true); define('WP_ACCESSIBLE_HOSTS','');
            $_SERVER['HTTP_HOST'] = parse_url($c['wordpressOrigin'],PHP_URL_HOST) . (($port = parse_url($c['wordpressOrigin'],PHP_URL_PORT)) ? ':' . $port : '');
            $_SERVER['HTTPS'] = 'on'; $_SERVER['REQUEST_URI'] = '/'; $_SERVER['SERVER_PORT'] = (string)($port ?: 443);
            // WordPress bootstrap uses/unsets common global variable names.
            // Preserve our maintenance scope without altering WordPress globals.
            $fncpInitializerScope = compact('c','plugin','owner','configurationRaw','pluginRaw','ownerRaw','phase','db','name','user','prefix','assertMaterials');
            $fncpInitializationStage = 'SITE_SOURCE_BOOTSTRAP';
            require '/usr/src/wordpress/wp-load.php'; require_once ABSPATH . 'wp-admin/includes/upgrade.php';
            foreach ($fncpInitializerScope as $fncpInitializerName => $fncpInitializerValue) { ${$fncpInitializerName} = $fncpInitializerValue; }
            unset($fncpInitializerScope,$fncpInitializerName,$fncpInitializerValue);
            $fncpInitializationStage = 'SITE_OWNER_VALIDATION';
            if (is_blog_installed() || sanitize_user($owner['operatorLogin'],true) !== $owner['operatorLogin'] || sanitize_email($owner['operatorEmail']) !== $owner['operatorEmail']) { fncp_initialize_deny(); }
            $installed = wp_install($owner['siteTitle'],$owner['operatorLogin'],$owner['operatorEmail'],false,'',$owner['operatorPassword'],'en_US');
            $fncpInitializationStage = 'SITE_OWNER_CREATED';
            if (is_wp_error($installed) || !is_array($installed) || !isset($installed['user_id'])) { fncp_initialize_deny(); }
            $operator = get_user_by('id',(int)$installed['user_id']); if (!$operator || !wp_check_password($owner['operatorPassword'],$operator->user_pass,$operator->ID)) { fncp_initialize_deny(); }
            $operator->add_cap('fncp_manage_registrations');
            $fncpInitializationStage = 'SITE_CLOSED_OPTIONS';
            foreach (['blog_public'=>'0','users_can_register'=>'0','default_comment_status'=>'closed','default_ping_status'=>'closed','active_plugins'=>[]] as $key=>$value) { update_option($key,$value); }
            $fncpInitializationStage = 'SITE_REST_ROUTING';
            // The bridge uses /wp-json/ paths. Plain permalink defaults serve the
            // theme instead, so initialise the core route map before admission.
            $wp_rewrite->set_permalink_structure('/%postname%/');
            rest_api_register_rewrites();
            flush_rewrite_rules(false); // Database rules only; immutable Apache configuration.
            // Default demonstration posts/comments are not programme records or a launch.
            foreach (get_posts(['post_type'=>'any','post_status'=>'any','numberposts'=>-1,'fields'=>'ids']) as $id) { wp_delete_post($id,true); }
            foreach (get_comments(['status'=>'all','number'=>0,'fields'=>'ids']) as $id) { wp_delete_comment($id,true); }
            $fncpInitializationStage = 'SITE_EMPTY_BRIDGE';
            $empty = ['schemaVersion'=>1,'configurationDigest'=>hash('sha256',fncp_initialize_canonical($plugin)),'lastObservedMs'=>0,'clockClosed'=>false,'registrations'=>[],'events'=>[]];
            if (!add_option('fncp_production_wordpress_v1',fncp_initialize_canonical($empty),'',false)
                || !add_option('fncp_fresh_install_v1',fncp_initialize_canonical(fncp_initialize_receipt($c,$plugin,$owner)),'',false)) { fncp_initialize_deny(); }
            if ($wpdb->last_error !== '') { fncp_initialize_deny(); }
        }
        require '/usr/src/wordpress/wp-includes/version.php';
        $fncpInitializationStage = 'SITE_SNAPSHOT_READ';
        $keys = ['siteurl','home','db_version','active_plugins','blog_public','users_can_register','default_comment_status','default_ping_status','permalink_structure','fncp_fresh_install_v1']; $options = [];
        foreach ($keys as $key) { $rows=$db->query("SELECT option_value FROM `{$prefix}options` WHERE option_name='".$db->real_escape_string($key)."'"); if ($rows->num_rows!==1) { fncp_initialize_deny(); } $options[$key]=(string)$rows->fetch_assoc()['option_value']; }
        $users=[]; $rows=$db->query("SELECT ID,user_login,user_email FROM `{$prefix}users`");
        while ($row=$rows->fetch_assoc()) { $caps=$db->query("SELECT meta_value FROM `{$prefix}usermeta` WHERE user_id=".(int)$row['ID']." AND meta_key='{$prefix}capabilities'");
            if ($caps->num_rows!==1) { fncp_initialize_deny(); } $raw=$caps->fetch_assoc()['meta_value']; $value=unserialize($raw,['allowed_classes'=>false]);
            if (!is_array($value) || serialize($value)!==$raw) { fncp_initialize_deny(); } $users[]=['login'=>$row['user_login'],'email'=>$row['user_email'],'capabilities'=>$value]; }
        $bridge=$db->query("SELECT option_value FROM `{$prefix}options` WHERE option_name='fncp_production_wordpress_v1'"); if ($bridge->num_rows!==1) { fncp_initialize_deny(); }
        $fncpInitializationStage = 'SITE_SNAPSHOT_VALIDATION';
        $rewrites=$db->query("SELECT option_value FROM `{$prefix}options` WHERE option_name='rewrite_rules'");
        if ($rewrites->num_rows!==1) { fncp_initialize_deny(); }
        fncp_initialize_assert_rewrites((string)$rewrites->fetch_assoc()['option_value']);
        if ((int)$db->query("SELECT COUNT(*) AS n FROM `{$prefix}posts`")->fetch_assoc()['n']!==0
            || (int)$db->query("SELECT COUNT(*) AS n FROM `{$prefix}comments`")->fetch_assoc()['n']!==0) { fncp_initialize_deny(); }
        fncp_initialize_assert_snapshot(['options'=>$options,'users'=>$users,'bridge'=>$bridge->fetch_assoc()['option_value']],$c,$plugin,$owner,(string)$wp_db_version);
        $assertMaterials();
        if ($phase === 'finalize') {
            $fncpInitializationStage = 'DATABASE_PRIVILEGE_FINALIZATION';
            $db->query("REVOKE CREATE,ALTER,DROP,INDEX ON `$name`.* FROM '$user'@'localhost'");
            $grantee=$db->real_escape_string("'$user'@'localhost'"); $privileges=[];
            $rows=$db->query("SELECT PRIVILEGE_TYPE,IS_GRANTABLE FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE='$grantee' AND TABLE_SCHEMA='$name'");
            while ($row=$rows->fetch_assoc()) { if ($row['IS_GRANTABLE']!=='NO') { fncp_initialize_deny(); } $privileges[]=$row['PRIVILEGE_TYPE']; }
            sort($privileges); if ($privileges!==['DELETE','INSERT','SELECT','UPDATE']) { fncp_initialize_deny(); }
            if ((int)$db->query("SELECT COUNT(*) AS n FROM information_schema.USER_PRIVILEGES WHERE GRANTEE='$grantee' AND PRIVILEGE_TYPE<>'USAGE'")->fetch_assoc()['n']!==0) { fncp_initialize_deny(); }
            if ((int)$db->query("SELECT COUNT(*) AS n FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE='$grantee' AND TABLE_SCHEMA<>'$name'")->fetch_assoc()['n']!==0) { fncp_initialize_deny(); }
            foreach (['TABLE_PRIVILEGES','COLUMN_PRIVILEGES'] as $scope) {
                if ((int)$db->query("SELECT COUNT(*) AS n FROM information_schema.$scope WHERE GRANTEE='$grantee'")->fetch_assoc()['n']!==0) { fncp_initialize_deny(); }
            }
            // MariaDB exposes routine/proxy privileges and role mappings in its
            // system tables. They must not enlarge the four direct DML grants.
            foreach (['procs_priv','proxies_priv','roles_mapping'] as $scope) {
                if ((int)$db->query("SELECT COUNT(*) AS n FROM mysql.$scope WHERE User='$user' AND Host='localhost'")->fetch_assoc()['n']!==0) { fncp_initialize_deny(); }
            }
            if ((int)$db->query("SELECT COUNT(*) AS n FROM mysql.user WHERE User='$user'")->fetch_assoc()['n']!==1
                || (int)$db->query("SELECT COUNT(*) AS n FROM mysql.global_priv WHERE User='$user' AND Host='localhost' AND COALESCE(JSON_VALUE(Priv,'$.default_role'),'')<>''")->fetch_assoc()['n']!==0) { fncp_initialize_deny(); }
        }
        $result = ['result'=>$phase==='site'?'CLOSED_SITE_INITIALIZED':'RUNTIME_DML_ONLY','operatorCount'=>1,'registrationCount'=>0,'eventCount'=>0,'samplePosts'=>0,'sampleComments'=>0,'mailSent'=>false,'participationOpened'=>false];
    }
    $db->query("SELECT RELEASE_LOCK('fncp_wordpress_initialize_v1')"); $db->close(); ob_end_clean(); fwrite(STDOUT,json_encode($result,JSON_THROW_ON_ERROR)."\n");
} catch (Throwable $e) {
    while (ob_get_level()) { ob_end_clean(); }
    $allowedStages = ['ENTRY','INPUT_VALIDATION','DATABASE_CONNECT','DATABASE_PRISTINE_CHECK','DATABASE_CREATE','SITE_PRISTINE_CHECK','SITE_RUNTIME_MATERIAL','SITE_SOURCE_BOOTSTRAP','SITE_OWNER_VALIDATION','SITE_OWNER_CREATED','SITE_CLOSED_OPTIONS','SITE_REST_ROUTING','SITE_EMPTY_BRIDGE','SITE_SNAPSHOT_READ','SITE_SNAPSHOT_VALIDATION','DATABASE_PRIVILEGE_FINALIZATION'];
    $safeStage = isset($fncpInitializationStage) && in_array($fncpInitializationStage,$allowedStages,true) ? $fncpInitializationStage : 'UNAVAILABLE';
    // No exception message, trace, SQL, credentials, paths or identity values.
    $safeFile = basename($e->getFile());
    if (!preg_match('/\A[a-zA-Z0-9_.-]+\.php\z/D',$safeFile)) { $safeFile = 'SOURCE'; }
    $safeClass = get_class($e); if (!preg_match('/\A[a-zA-Z0-9_\\\\]+\z/D',$safeClass)) { $safeClass='Throwable'; }
    fwrite(STDERR,"WordPress maintenance initialization rejected; any partial database is not reusable.\n");
    fwrite(STDERR,json_encode(['stage'=>$safeStage,'source'=>$safeFile,'line'=>$e->getLine(),'exceptionClass'=>$safeClass],JSON_THROW_ON_ERROR)."\n"); exit(1);
}
