<?php
// PHP's development server is local proof only, never an Internet webserver.
if (PHP_SAPI !== 'cli-server' || getenv('FNCP_LOCAL_SYNTHETIC_MODE') !== 'fixture-only' ||
    ($_SERVER['HTTP_HOST'] ?? '') !== '127.0.0.1:8102' || ($_SERVER['REMOTE_ADDR'] ?? '') !== '127.0.0.1') {
    http_response_code(403); exit('Local synthetic proof only.');
}
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; form-action 'self'");
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if (preg_match('/wp-config|\.\.|%|\\\\|\.json|\.sql|\.zip|\.gz/i', $path)) { http_response_code(403); exit; }
return false;
