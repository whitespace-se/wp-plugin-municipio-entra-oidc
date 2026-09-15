# Municipio Entra OIDC

Shared WordPress integration between Microsoft Entra ID, OpenID Connect Generic
Client and Municipio user groups.

The plugin does not implement OIDC. It adds fail-closed policy around the
GPL-licensed `daggerhart/openid-connect-generic` protocol client:

- automatic Entra redirect for public requests to the canonical WordPress login
  URL;
- normal WordPress password login on that same URL from configured networks;
- server-side rejection of public password login attempts;
- tenant validation in addition to the OIDC client's issuer and audience
  validation;
- deterministic Entra app-role or group mapping to Municipio's `user_group`
  taxonomy;
- just-in-time user creation only when a configured authorization claim matches.

Authorization is applied at the validated ID-token boundary for both new and
returning users. OpenID Connect Generic 3.11.3 documents a
`openid-connect-generic-user-login-test` hook but does not invoke it, so this
integration does not rely on that hook.

## Required configuration

Define configuration outside the repository before activating the integration:

```php
define('MUNICIPIO_ENTRA_OIDC_TENANT_ID', '00000000-0000-0000-0000-000000000000');
// Keep this off during parallel acceptance; switch to 1 for the final cutover.
define('MUNICIPIO_ENTRA_OIDC_ENFORCE_LOGIN_POLICY', 0);
define('MUNICIPIO_ENTRA_OIDC_LOCAL_LOGIN_ALLOWED_IPS', [
    '178.73.217.218',
    '2a02:752:0:18::16b5',
]);
define('MUNICIPIO_ENTRA_OIDC_AUTHORIZATION_CLAIM', 'roles');
define('MUNICIPIO_ENTRA_OIDC_USER_GROUP_MAP', [
    // Declaration order is priority order.
    'Municipio.Editor' => 'Redaktör',
    'Municipio.Employee' => 'Medarbetare',
]);
define('MUNICIPIO_ENTRA_OIDC_LOGIN_BUTTON_TEXT', 'Logga in med Microsoft');
```

Configure OpenID Connect Generic with a tenant-specific issuer, audience and
JWKS endpoint. Use its alternate callback URI and keep existing-user linking
disabled for protected local administrator accounts.

Installing the package does not enforce redirect or password policy. Enforcement
requires the explicit flag above, a complete OIDC client configuration and a
non-empty authorization map. This keeps the normal login available while the
Entra button is tested during a parallel acceptance period.

Application roles are preferred. Assign the roles to existing Entra groups and
map the emitted `roles` values above. A `groups` claim and group Object IDs can
be used instead, but Entra group-overage responses are deliberately not resolved
by this plugin and must be avoided or handled separately.

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
