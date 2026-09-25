<?php

declare(strict_types=1);

namespace Whitespace\MunicipioEntraOidc;

final class Configuration
{
    /** @param array<string, mixed> $overrides */
    public function __construct(private array $overrides = [])
    {
    }

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
        return $this->tenantIds()[0] ?? '';
    }

    /** @return list<string> */
    public function tenantIds(): array
    {
        $value = $this->constant('MUNICIPIO_ENTRA_OIDC_ALLOWED_TENANT_IDS', []);
        $values = is_array($value) ? $value : [];

        if ($values === []) {
            $values[] = $this->constant('MUNICIPIO_ENTRA_OIDC_TENANT_ID', '');
        }

        $tenantIds = [];

        foreach ($values as $tenantId) {
            if (!is_string($tenantId)) {
                continue;
            }

            $tenantId = strtolower(trim($tenantId));

            if ($this->isTenantId($tenantId)) {
                $tenantIds[$tenantId] = $tenantId;
            }
        }

        return array_values($tenantIds);
    }

    /** @return array<mixed, mixed> */
    public function userGroupMapForTenant(string $tenantId): array
    {
        $mapping = $this->userGroupMap();

        foreach ($mapping as $configuredTenantId => $tenantMapping) {
            if (
                is_string($configuredTenantId)
                && hash_equals(strtolower(trim($configuredTenantId)), strtolower(trim($tenantId)))
                && is_array($tenantMapping)
            ) {
                return $tenantMapping;
            }
        }

        // Preserve the original flat-map format for single-tenant installs.
        if (count($this->tenantIds()) === 1) {
            return $mapping;
        }

        return [];
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

        if ($this->tenantIds() === []) {
            return false;
        }

        foreach ($this->tenantIds() as $tenantId) {
            if ($this->userGroupMapForTenant($tenantId) === []) {
                return false;
            }
        }

        return true;
    }

    public function isLoginPolicyEnforced(): bool
    {
        $value = $this->constant('MUNICIPIO_ENTRA_OIDC_ENFORCE_LOGIN_POLICY', false);

        return $value === true || $value === 1 || $value === '1';
    }

    private function constant(string $name, mixed $fallback): mixed
    {
        if (array_key_exists($name, $this->overrides)) {
            return $this->overrides[$name];
        }

        return defined($name) ? constant($name) : $fallback;
    }

    private function isTenantId(string $tenantId): bool
    {
        return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/D', $tenantId) === 1;
    }
}
