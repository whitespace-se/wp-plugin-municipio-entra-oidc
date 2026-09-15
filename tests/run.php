<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/ClaimMapper.php';
require_once __DIR__ . '/../src/Configuration.php';
require_once __DIR__ . '/../src/NetworkMatcher.php';
require_once __DIR__ . '/../src/Plugin.php';

use Whitespace\MunicipioEntraOidc\ClaimMapper;
use Whitespace\MunicipioEntraOidc\Configuration;
use Whitespace\MunicipioEntraOidc\NetworkMatcher;
use Whitespace\MunicipioEntraOidc\Plugin;

if (!class_exists('WP_Error')) {
    class WP_Error
    {
        public function __construct(public string $code, public string $message)
        {
        }
    }
}

define('MUNICIPIO_ENTRA_OIDC_TENANT_ID', 'tenant-id');
define('MUNICIPIO_ENTRA_OIDC_LOCAL_LOGIN_ALLOWED_IPS', [
    '178.73.217.218',
    '2a02:752:0:18::16b5',
]);
define('MUNICIPIO_ENTRA_OIDC_AUTHORIZATION_CLAIM', 'roles');
define('MUNICIPIO_ENTRA_OIDC_USER_GROUP_MAP', [
    'Nora.Editor' => 'Redaktör',
    'Nora.Employee' => 'Medarbetare',
]);
define('MUNICIPIO_ENTRA_OIDC_LOGIN_BUTTON_TEXT', 'Logga in med Microsoft');
define('MUNICIPIO_ENTRA_OIDC_ENFORCE_LOGIN_POLICY', 1);
define('OIDC_CLIENT_ID', 'client-id');
define('OIDC_CLIENT_SECRET', 'client-secret');
define('OIDC_ENDPOINT_LOGIN_URL', 'https://login.example.test/authorize');
define('OIDC_ENDPOINT_TOKEN_URL', 'https://login.example.test/token');
define('OIDC_ENDPOINT_JWKS_URL', 'https://login.example.test/keys');
define('OIDC_ISSUER', 'https://login.example.test/issuer');

$failures = [];

$assert = static function (bool $condition, string $message) use (&$failures): void {
    if (!$condition) {
        $failures[] = $message;
    }
};

$networkMatcher = new NetworkMatcher();
$assert($networkMatcher->matches('178.73.217.218', ['178.73.217.218']), 'Exact VPN IPv4 must match.');
$assert($networkMatcher->matches('178.73.217.218', ['178.73.217.0/24']), 'VPN IPv4 CIDR must match.');
$assert(!$networkMatcher->matches('178.73.217.219', ['178.73.217.218']), 'Other IPv4 must not match.');
$assert($networkMatcher->matches('2a02:752:0:18::16b5', ['2a02:752:0:18::/64']), 'VPN IPv6 CIDR must match.');
$assert(!$networkMatcher->matches('not-an-ip', ['0.0.0.0/0']), 'Malformed address must fail closed.');
$assert(!$networkMatcher->matches('178.73.217.218', ['178.73.217.218:6039']), 'Address with VPN service port must not match.');

$claimMapper = new ClaimMapper();
$mapping = [
    'Nora.Editor' => 'Redaktör',
    'Nora.Employee' => 'Medarbetare',
];
$assert(
    $claimMapper->resolve(['roles' => ['Nora.Employee', 'Nora.Editor']], 'roles', $mapping) === 'Redaktör',
    'Mapping declaration order must determine precedence.',
);
$assert(
    $claimMapper->resolve(['roles' => 'Nora.Employee'], 'roles', $mapping) === 'Medarbetare',
    'A scalar role claim must map.',
);
$assert(
    $claimMapper->resolve(['roles' => ['Unknown']], 'roles', $mapping) === null,
    'An unmapped role must fail closed.',
);
$assert(
    $claimMapper->resolve([], 'roles', $mapping) === null,
    'A missing authorization claim must fail closed.',
);

$configuration = new Configuration();
$vpnPlugin = new Plugin(
    $configuration,
    $networkMatcher,
    $claimMapper,
    ['REMOTE_ADDR' => '178.73.217.218', 'REQUEST_METHOD' => 'GET'],
);
$publicPlugin = new Plugin(
    $configuration,
    $networkMatcher,
    $claimMapper,
    ['REMOTE_ADDR' => '203.0.113.10', 'REQUEST_METHOD' => 'GET'],
);
$vpnSettings = $vpnPlugin->configureOidcClient((object) []);
$publicSettings = $publicPlugin->configureOidcClient((object) []);
$assert($vpnSettings->login_type === 'button', 'VPN login must retain the WordPress login page.');
$assert($publicSettings->login_type === 'auto', 'Public login must redirect automatically to Entra.');
$assert($publicSettings->alternate_redirect_uri === 1, 'The callback must use the clean alternate URI.');
$assert($publicSettings->identity_key === 'oid', 'The Entra object ID must be used as plugin identity.');
$assert(
    $publicPlugin->authorizeOidcLogin(true, ['tid' => 'TENANT-ID', 'roles' => ['Nora.Employee']]),
    'A mapped role from the configured tenant must be authorized.',
);
$assert(
    !$publicPlugin->authorizeOidcLogin(true, ['tid' => 'other-tenant', 'roles' => ['Nora.Employee']]),
    'A different tenant must be rejected.',
);
$assert(
    !$publicPlugin->authorizeOidcLogin(true, ['tid' => 'tenant-id', 'roles' => ['Unknown']]),
    'An unmapped role must be rejected.',
);
$assert(
    is_array($publicPlugin->authorizeIdTokenClaims(['tid' => 'tenant-id', 'roles' => ['Nora.Editor']])),
    'An authorized ID-token claim must pass through.',
);
$assert(
    $publicPlugin->authorizeIdTokenClaims(['tid' => 'other-tenant', 'roles' => ['Nora.Editor']]) instanceof WP_Error,
    'An unauthorized ID-token claim must be rejected before user lookup and login.',
);
$normalizedClaims = $publicPlugin->normalizeUserClaim(['preferred_username' => 'person@example.test']);
$assert(
    isset($normalizedClaims['email']) && $normalizedClaims['email'] === 'person@example.test',
    'A valid preferred username must provide a missing email claim for account creation.',
);

$publicPostPlugin = new Plugin(
    $configuration,
    $networkMatcher,
    $claimMapper,
    ['REMOTE_ADDR' => '203.0.113.10', 'REQUEST_METHOD' => 'POST'],
);
$vpnPostPlugin = new Plugin(
    $configuration,
    $networkMatcher,
    $claimMapper,
    ['REMOTE_ADDR' => '178.73.217.218', 'REQUEST_METHOD' => 'POST'],
);
$assert(
    $publicPostPlugin->blockPublicPasswordLogin(null, 'local-admin', 'not-a-real-password') instanceof WP_Error,
    'Public WordPress password POST must be rejected server-side.',
);
$assert(
    $vpnPostPlugin->blockPublicPasswordLogin(null, 'local-admin', 'not-a-real-password') === null,
    'VPN WordPress password POST must remain available.',
);
$assert(
    $publicPlugin->blockPublicPasswordLogin(null, 'local-admin', 'not-a-real-password') instanceof WP_Error,
    'Password authentication outside wp-login.php must not bypass the network policy.',
);

if ($failures !== []) {
    foreach ($failures as $failure) {
        fwrite(STDERR, "FAIL: {$failure}\n");
    }

    exit(1);
}

fwrite(STDOUT, "All tests passed.\n");
