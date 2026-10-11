<?php
if (!defined('ABSPATH')) { exit; }
// This role serves approval administration and its signed service RPC. Mail,
// upgrades and arbitrary external HTTP belong to separately reviewed services.
add_filter('pre_wp_mail', static fn() => false, PHP_INT_MAX);
add_filter('pre_http_request', static function ($pre, $arguments, $url) {
    try { $c = fncp_production_configuration(); if ($url === $c['eventEndpoint']) { return $pre; } } catch (Throwable $e) {}
    return new WP_Error('fncp_http_unavailable', 'Request unavailable.');
}, PHP_INT_MAX, 3);
add_filter('get_avatar_url', static fn() => '');
require_once __DIR__ . '/fncp-production/fncp-production-wordpress.php';
