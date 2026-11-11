# Municipio Entra OIDC

Shared WordPress integration between Microsoft Entra ID, OpenID Connect Generic
Client, WordPress roles and Municipio user groups.

The plugin does not implement OIDC. It adds fail-closed policy around the
GPL-licensed `daggerhart/openid-connect-generic` protocol client:

- automatic Entra redirect for public requests to the canonical WordPress login
  URL;
- normal WordPress password login on that same URL from configured networks;
- server-side rejection of public password login attempts;
- tenant validation in addition to the OIDC client's issuer and audience
  validation;
- a default WordPress role for every authenticated user in an allowed tenant;
- deterministic Entra app-role or group mapping to elevated WordPress roles and,
  where needed, Municipio's `user_group` taxonomy;
- a styled Entra button above the normal WordPress login form during parallel
  acceptance.

Authorization is applied at the validated ID-token boundary for both new and
returning users. OpenID Connect Generic 3.11.3 documents a
`openid-connect-generic-user-login-test` hook but does not invoke it, so this
integration does not rely on that hook.

## Required configuration

Define configuration outside the repository before activating the integration:

```php
define('MUNICIPIO_ENTRA_OIDC_ALLOWED_TENANT_IDS', [
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000002',
]);
// Keep this off during parallel acceptance; switch to 1 for the final cutover.
define('MUNICIPIO_ENTRA_OIDC_ENFORCE_LOGIN_POLICY', 0);
define('MUNICIPIO_ENTRA_OIDC_LOCAL_LOGIN_ALLOWED_IPS', [
    '178.73.217.218',
    '2a02:752:0:18::16b5',
]);
define('MUNICIPIO_ENTRA_OIDC_AUTHORIZATION_CLAIM', 'groups');
define('MUNICIPIO_ENTRA_OIDC_DEFAULT_ROLE_MAP', [
    '00000000-0000-0000-0000-000000000001' => 'subscriber',
    '00000000-0000-0000-0000-000000000002' => 'subscriber',
]);
define('MUNICIPIO_ENTRA_OIDC_ROLE_MAP', [
    '00000000-0000-0000-0000-000000000001' => [
        // Declaration order within each tenant is priority order.
        '00000000-0000-0000-0000-000000000101' => 'administrator',
        '00000000-0000-0000-0000-000000000102' => 'editor',
    ],
    '00000000-0000-0000-0000-000000000002' => [
        '00000000-0000-0000-0000-000000000201' => 'administrator',
        '00000000-0000-0000-0000-000000000202' => 'editor',
    ],
]);
// Optional: map the same claim to Municipio user-group terms when a site uses
// that taxonomy for content targeting.
define('MUNICIPIO_ENTRA_OIDC_USER_GROUP_MAP', []);
define('MUNICIPIO_ENTRA_OIDC_LOGIN_BUTTON_TEXT', 'Logga in med Microsoft');
```

Configure OpenID Connect Generic with a tenant-specific issuer, audience and
JWKS endpoint. Use its alternate callback URI and keep existing-user linking
disabled for protected local administrator accounts.

Installing the package does not enforce redirect or password policy. Enforcement
requires the explicit flag above, a complete OIDC client configuration and a
tenant authorization rule for every allowed tenant. A default role authorizes
every valid account in that tenant; role and user-group maps can instead be used
for claim-only authorization. This keeps the normal login available while the
Entra button is tested during a parallel acceptance period.

Application roles are preferred for new integrations. Existing Entra group
Object IDs can also be mapped from the `groups` claim. If a default role is
configured, an Entra group-overage response safely falls back to that role and
never grants an elevated role. Without a default role, group overage is rejected
because the authorization claim cannot be evaluated safely.

Mappings are scoped by tenant so a claim value from one tenant cannot inherit a
different tenant's authorization. Unknown tenants, missing claims and Entra
group-overage responses are rejected. The legacy `MUNICIPIO_ENTRA_OIDC_TENANT_ID`
and flat map remain supported for single-tenant installations.

The allowlist does not by itself make the protocol client multi-tenant. The
client's issuer mode must still be configured and validated for the chosen
single-tenant, guest-account or multi-tenant model.

## Network trust

The local-login decision reads only `REMOTE_ADDR`. Deploy it where the web
server is the public edge. If a reverse proxy or CDN is introduced, establish
and test a trusted proxy chain before translating a forwarded address into
`REMOTE_ADDR`.

The VPN service port is not part of the HTTP address allowlist. For example,
`178.73.217.218:6039` is represented as the egress address
`178.73.217.218`.

## Tests

```sh
composer test
```
