<?php

declare(strict_types=1);

namespace Whitespace\MunicipioEntraOidc;

final class Configuration
{
    /** @return array<int, mixed> */
    public function localLoginNetworks(): array
    {
        $value = $this->constant('MUNICIPIO_ENTRA_OIDC_LOCAL_LOGIN_ALLOWED_IPS', []);

        return is_array($value) ? array_values($value) : [];
    }

    /** @return array<mixed, mixed> */
    public function userGroupMap(): array
    {
        $value = $this->constant('MUNICIPIO_ENTRA_OIDC_USER_GROUP_MAP', []);

        return is_array($value) ? $value : [];
    }

    public function authorizationClaim(): string
    {
        $value = $this->constant('MUNICIPIO_ENTRA_OIDC_AUTHORIZATION_CLAIM', 'roles');

        return is_string($value) && trim($value) !== '' ? trim($value) : 'roles';
    }

    public function tenantId(): string
    {
        $value = $this->constant('MUNICIPIO_ENTRA_OIDC_TENANT_ID', '');

        return is_string($value) ? trim($value) : '';
    }

    public function loginButtonText(): string
    {
        $value = $this->constant('MUNICIPIO_ENTRA_OIDC_LOGIN_BUTTON_TEXT', 'Log in with Microsoft');

        return is_string($value) && trim($value) !== '' ? trim($value) : 'Log in with Microsoft';
    }

    public function isOidcConfigured(): bool
    {
        foreach (['OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET', 'OIDC_ENDPOINT_LOGIN_URL', 'OIDC_ENDPOINT_TOKEN_URL', 'OIDC_ENDPOINT_JWKS_URL', 'OIDC_ISSUER'] as $name) {
            if (!defined($name) || !is_string(constant($name)) || trim((string) constant($name)) === '') {
                return false;
            }
        }

        return $this->tenantId() !== '' && $this->userGroupMap() !== [];
    }

    public function isLoginPolicyEnforced(): bool
    {
        $value = $this->constant('MUNICIPIO_ENTRA_OIDC_ENFORCE_LOGIN_POLICY', false);

        return $value === true || $value === 1 || $value === '1';
    }

    private function constant(string $name, mixed $fallback): mixed
    {
        return defined($name) ? constant($name) : $fallback;
    }
}
