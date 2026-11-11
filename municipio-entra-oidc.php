<?php

/**
 * Plugin Name: Municipio Entra OIDC
 * Description: Enforces Microsoft Entra OIDC login policy and maps authorization claims to WordPress roles and Municipio user groups.
 * Version: 0.3.1
 * Requires PHP: 8.0
 * License: GPL-2.0-or-later
 */

declare(strict_types=1);

if (!function_exists('add_filter')) {
    return;
}

require_once __DIR__ . '/src/ClaimMapper.php';
require_once __DIR__ . '/src/Configuration.php';
require_once __DIR__ . '/src/NetworkMatcher.php';
require_once __DIR__ . '/src/Plugin.php';

(new Whitespace\MunicipioEntraOidc\Plugin())->register();

/*
 * This package requires the protocol client and is installed as a must-use
 * plugin. Load the client before WordPress reaches `init` so the integration
 * does not depend on a separate database activation flag. A later normal
 * plugin load is harmless because WordPress uses require_once.
 */
$oidcClientPlugin = defined('WP_PLUGIN_DIR')
    ? WP_PLUGIN_DIR . '/openid-connect-generic/openid-connect-generic.php'
    : '';

if (!class_exists('OpenID_Connect_Generic', false) && is_file($oidcClientPlugin)) {
    require_once $oidcClientPlugin;
}

unset($oidcClientPlugin);
