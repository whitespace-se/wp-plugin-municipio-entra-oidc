<?php

/**
 * Plugin Name: Municipio Entra OIDC
 * Description: Enforces Microsoft Entra OIDC login policy and maps authorization claims to Municipio user groups.
 * Version: 0.1.1
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
