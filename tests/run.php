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

$registeredFilters = [];

if (!function_exists('add_filter')) {
    function add_filter(string $hook, mixed $callback, int $priority = 10, int $acceptedArgs = 1): bool
    {
        global $registeredFilters;
        $registeredFilters[$hook][] = [$callback, $priority, $acceptedArgs];

        return true;
    }
}

if (!function_exists('add_action')) {
    function add_action(string $hook, mixed $callback, int $priority = 10, int $acceptedArgs = 1): bool
    {
        return add_filter($hook, $callback, $priority, $acceptedArgs);
    }
}

if (!class_exists('WP_Error')) {
    class WP_Error
    {
        public function __construct(public string $code, public string $message)
        {
        }
    }
}

if (!class_exists('OpenID_Connect_Generic')) {
    class OpenID_Connect_Generic
    {
    }
}

define('MUNICIPIO_ENTRA_OIDC_TENANT_ID', '11111111-1111-4111-8111-111111111111');
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
$publicPlugin->register();
$authenticateRegistration = $registeredFilters['authenticate'][0] ?? null;
$assert(
    is_array($authenticateRegistration)
        && $authenticateRegistration[1] === PHP_INT_MAX
        && $authenticateRegistration[2] === 3,
    'The password policy must run after every core authentication handler.',
);
$vpnSettings = $vpnPlugin->configureOidcClient((object) []);
$publicSettings = $publicPlugin->configureOidcClient((object) []);
$assert($vpnSettings->login_type === 'button', 'VPN login must retain the WordPress login page.');
$assert($publicSettings->login_type === 'auto', 'Public login must redirect automatically to Entra.');
$assert($publicSettings->alternate_redirect_uri === 1, 'The callback must use the clean alternate URI.');
$assert($publicSettings->identity_key === 'oid', 'The Entra object ID must be used as plugin identity.');
$assert(
    $publicPlugin->authorizeOidcLogin(true, ['tid' => '11111111-1111-4111-8111-111111111111', 'roles' => ['Nora.Employee']]),
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
    is_array($publicPlugin->authorizeIdTokenClaims(['tid' => '11111111-1111-4111-8111-111111111111', 'roles' => ['Nora.Editor']])),
    'An authorized ID-token claim must pass through.',
);
$assert(
    $publicPlugin->authorizeIdTokenClaims(['tid' => 'other-tenant', 'roles' => ['Nora.Editor']]) instanceof WP_Error,
    'An unauthorized ID-token claim must be rejected before user lookup and login.',
);

$tenantA = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
$tenantB = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
$multiTenantConfiguration = new Configuration([
    'MUNICIPIO_ENTRA_OIDC_ALLOWED_TENANT_IDS' => [strtoupper($tenantA), $tenantB, 'not-a-tenant-id', $tenantA],
    'MUNICIPIO_ENTRA_OIDC_AUTHORIZATION_CLAIM' => 'groups',
    'MUNICIPIO_ENTRA_OIDC_USER_GROUP_MAP' => [
        $tenantA => [
            'group-a' => 'Nora',
            'shared-looking-group' => 'Nora shared',
        ],
        $tenantB => [
            'group-b' => 'Brandkåren',
        ],
    ],
]);
$multiTenantPlugin = new Plugin($multiTenantConfiguration, $networkMatcher, $claimMapper);
$assert(
    $multiTenantConfiguration->tenantIds() === [$tenantA, $tenantB],
    'Tenant IDs must be normalized, validated and deduplicated.',
);
$assert(
    $multiTenantPlugin->authorizeOidcLogin(true, ['tid' => $tenantA, 'groups' => ['group-a']]),
    'A mapped group from the first allowed tenant must be authorized.',
);
$assert(
    $multiTenantPlugin->authorizeOidcLogin(true, ['tid' => $tenantB, 'groups' => ['group-b']]),
    'A mapped group from the second allowed tenant must be authorized.',
);
$assert(
    !$multiTenantPlugin->authorizeOidcLogin(true, ['tid' => $tenantB, 'groups' => ['shared-looking-group']]),
    'A mapping from one tenant must never authorize the same claim value from another tenant.',
);
$assert(
    !$multiTenantPlugin->authorizeOidcLogin(true, ['tid' => 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', 'groups' => ['group-a']]),
    'A tenant outside the explicit allowlist must be rejected.',
);
$assert(
    !$multiTenantPlugin->authorizeOidcLogin(true, [
        'tid' => $tenantA,
        'groups' => ['group-a'],
        '_claim_names' => ['groups' => 'src1'],
    ]),
    'A groups overage response must fail closed even if a groups value is also present.',
);
$assert(
    !$multiTenantPlugin->authorizeOidcLogin(true, ['tid' => $tenantA]),
    'A missing groups claim must fail closed.',
);
$unsafeFlatMultiTenantConfiguration = new Configuration([
    'MUNICIPIO_ENTRA_OIDC_ALLOWED_TENANT_IDS' => [$tenantA, $tenantB],
    'MUNICIPIO_ENTRA_OIDC_USER_GROUP_MAP' => ['group-a' => 'Nora'],
]);
$assert(
    $unsafeFlatMultiTenantConfiguration->userGroupMapForTenant($tenantA) === [],
    'A flat map must not be reused across multiple tenants.',
);
$incompleteMultiTenantConfiguration = new Configuration([
    'MUNICIPIO_ENTRA_OIDC_ALLOWED_TENANT_IDS' => [$tenantA, $tenantB],
    'MUNICIPIO_ENTRA_OIDC_USER_GROUP_MAP' => [$tenantA => ['group-a' => 'Nora']],
    'OIDC_CLIENT_ID' => 'client-id',
    'OIDC_CLIENT_SECRET' => 'client-secret',
    'OIDC_ENDPOINT_LOGIN_URL' => 'https://login.example.test/authorize',
    'OIDC_ENDPOINT_TOKEN_URL' => 'https://login.example.test/token',
    'OIDC_ENDPOINT_JWKS_URL' => 'https://login.example.test/keys',
    'OIDC_ISSUER' => 'https://login.example.test/issuer',
]);
$assert(
    !$incompleteMultiTenantConfiguration->isOidcConfigured(),
    'Automatic enforcement must remain disabled until every allowed tenant has a mapping.',
);

$defaultRoleConfiguration = new Configuration([
    'MUNICIPIO_ENTRA_OIDC_ALLOWED_TENANT_IDS' => [$tenantA, $tenantB],
    'MUNICIPIO_ENTRA_OIDC_AUTHORIZATION_CLAIM' => 'groups',
    'MUNICIPIO_ENTRA_OIDC_DEFAULT_ROLE_MAP' => [
        $tenantA => 'subscriber',
        $tenantB => 'subscriber',
    ],
    'MUNICIPIO_ENTRA_OIDC_ROLE_MAP' => [
        $tenantA => [
            'admin-a' => 'administrator',
            'editor-a' => 'editor',
        ],
        $tenantB => [
            'admin-b' => 'administrator',
            'editor-b' => 'editor',
        ],
    ],
    'OIDC_CLIENT_ID' => 'client-id',
    'OIDC_CLIENT_SECRET' => 'client-secret',
    'OIDC_ENDPOINT_LOGIN_URL' => 'https://login.example.test/authorize',
    'OIDC_ENDPOINT_TOKEN_URL' => 'https://login.example.test/token',
    'OIDC_ENDPOINT_JWKS_URL' => 'https://login.example.test/keys',
    'OIDC_ISSUER' => 'https://login.example.test/issuer',
]);
$defaultRolePlugin = new Plugin($defaultRoleConfiguration, $networkMatcher, $claimMapper);
$assert(
    $defaultRoleConfiguration->isOidcConfigured(),
    'A default role must be a complete tenant authorization rule.',
);
$assert(
    $defaultRolePlugin->authorizeOidcLogin(true, ['tid' => $tenantA]),
    'Every valid account in a tenant with a default role must be authorized.',
);
$assert(
    !$defaultRolePlugin->authorizeOidcLogin(true, ['tid' => 'cccccccc-cccc-4ccc-8ccc-cccccccccccc']),
    'A default role must never authorize an unknown tenant.',
);

$subscriber = new class {
    public int $ID = 1;
    public ?string $role = null;

    public function set_role(string $role): void
    {
        $this->role = $role;
    }
};
$editor = clone $subscriber;
$administrator = clone $subscriber;
$overageUser = clone $subscriber;
$defaultRolePlugin->synchronizeWordPressRole($subscriber, ['tid' => $tenantA]);
$defaultRolePlugin->synchronizeWordPressRole($editor, ['tid' => $tenantA, 'groups' => ['editor-a']]);
$defaultRolePlugin->synchronizeWordPressRole($administrator, ['tid' => $tenantA, 'groups' => ['editor-a', 'admin-a']]);
$defaultRolePlugin->synchronizeWordPressRole($overageUser, [
    'tid' => $tenantA,
    'groups' => ['admin-a'],
    '_claim_names' => ['groups' => 'src1'],
]);
$assert($subscriber->role === 'subscriber', 'A user without a mapped group must receive the tenant default role.');
$assert($editor->role === 'editor', 'An editor group must elevate the user to editor.');
$assert($administrator->role === 'administrator', 'Mapping declaration order must make administrator win over editor.');
$assert($overageUser->role === 'subscriber', 'Group overage must fall back to subscriber and never elevate a user.');
$assert(
    str_contains($defaultRolePlugin->appendLocalLoginSeparator(''), 'municipio-entra-local-login-separator'),
    'The Entra button area must be separated from the fallback WordPress form.',
);
$assert(
    substr_count($defaultRolePlugin->appendLocalLoginSeparator('<div class="municipio-entra-local-login-separator"></div>'), 'municipio-entra-local-login-separator') === 1,
    'The fallback separator must not be added twice.',
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
