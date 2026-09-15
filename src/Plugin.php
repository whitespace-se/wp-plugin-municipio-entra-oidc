<?php

declare(strict_types=1);

namespace Whitespace\MunicipioEntraOidc;

final class Plugin
{
    private Configuration $configuration;
    private NetworkMatcher $networkMatcher;
    private ClaimMapper $claimMapper;
    /** @var array<string, mixed>|null */
    private ?array $server;

    /** @param array<string, mixed>|null $server */
    public function __construct(
        ?Configuration $configuration = null,
        ?NetworkMatcher $networkMatcher = null,
        ?ClaimMapper $claimMapper = null,
        ?array $server = null,
    ) {
        $this->configuration = $configuration ?? new Configuration();
        $this->networkMatcher = $networkMatcher ?? new NetworkMatcher();
        $this->claimMapper = $claimMapper ?? new ClaimMapper();
        $this->server = $server;
    }

    public function register(): void
    {
        add_filter('openid-connect-generic-settings', [$this, 'configureOidcClient'], PHP_INT_MAX);
        add_filter('openid-connect-generic-login-button-text', [$this, 'loginButtonText']);
        add_filter('openid-connect-modify-id-token-claim-before-validation', [$this, 'authorizeIdTokenClaims']);
        add_filter('openid-connect-generic-alter-user-claim', [$this, 'normalizeUserClaim']);
        add_filter('openid-connect-generic-user-creation-test', [$this, 'authorizeOidcLogin'], 10, 2);
        add_action('openid-connect-generic-user-create', [$this, 'synchronizeUserGroup'], 10, 2);
        add_action('openid-connect-generic-update-user-using-current-claim', [$this, 'synchronizeUserGroup'], 10, 2);
        add_filter('authenticate', [$this, 'blockPublicPasswordLogin'], 1, 3);
    }

    public function configureOidcClient(object $settings): object
    {
        // Never trigger automatic SSO from an incomplete configuration.
        $settings->login_type = $this->configuration->isOidcConfigured()
            && $this->configuration->isLoginPolicyEnforced()
            && !$this->isLocalLoginAllowed()
            ? 'auto'
            : 'button';
        $settings->alternate_redirect_uri = 1;
        $settings->identity_key = 'oid';
        $settings->nickname_key = 'preferred_username';
        $settings->email_format = '{email}';
        $settings->displayname_format = '{name}';

        return $settings;
    }

    public function loginButtonText(string $text): string
    {
        return $this->configuration->loginButtonText();
    }

    /**
     * The upstream client's documented user-login-test filter is not invoked
     * in 3.11.3. Validate authorization at the ID-token boundary so the rule
     * applies to both returning and newly-created users.
     *
     * @param mixed $claims
     * @return array<string, mixed>|\WP_Error|mixed
     */
    public function authorizeIdTokenClaims(mixed $claims): mixed
    {
        if (!is_array($claims) || !$this->authorizeOidcLogin(true, $claims)) {
            return class_exists('WP_Error')
                ? new \WP_Error('municipio_entra_oidc_cannot_authorize', 'Your Entra account is not authorized for this website.')
                : $claims;
        }

        return $claims;
    }

    /** @param array<string, mixed> $claims */
    public function normalizeUserClaim(array $claims): array
    {
        if (
            (!isset($claims['email']) || !is_string($claims['email']) || trim($claims['email']) === '')
            && isset($claims['preferred_username'])
            && is_string($claims['preferred_username'])
            && filter_var($claims['preferred_username'], FILTER_VALIDATE_EMAIL)
        ) {
            $claims['email'] = trim($claims['preferred_username']);
        }

        return $claims;
    }

    /**
     * @param array<string, mixed> $claims
     */
    public function authorizeOidcLogin(bool $authorized, array $claims): bool
    {
        if (!$authorized || !$this->claimsBelongToConfiguredTenant($claims)) {
            return false;
        }

        return $this->resolveUserGroup($claims) !== null;
    }

    /**
     * @param mixed                $user
     * @param array<string, mixed> $claims
     */
    public function synchronizeUserGroup(mixed $user, array $claims): void
    {
        $userId = is_object($user) && isset($user->ID) ? (int) $user->ID : 0;
        $userGroup = $this->resolveUserGroup($claims);

        if ($userId < 1 || $userGroup === null || !function_exists('wp_set_object_terms')) {
            return;
        }

        $switched = false;

        if (function_exists('is_multisite') && is_multisite() && function_exists('get_main_site_id') && function_exists('switch_to_blog')) {
            switch_to_blog((int) get_main_site_id());
            $switched = true;
        }

        try {
            $term = function_exists('term_exists') ? term_exists($userGroup, 'user_group') : null;

            if (!$term && function_exists('wp_insert_term')) {
                $term = wp_insert_term($userGroup, 'user_group');
            }

            if (is_array($term) && isset($term['term_id'])) {
                wp_set_object_terms($userId, (int) $term['term_id'], 'user_group', false);
            } elseif (is_int($term)) {
                wp_set_object_terms($userId, $term, 'user_group', false);
            }
        } finally {
            if ($switched && function_exists('restore_current_blog')) {
                restore_current_blog();
            }
        }
    }

    public function blockPublicPasswordLogin(mixed $user, string $username, string $password): mixed
    {
        if (
            !$this->configuration->isOidcConfigured()
            || !$this->configuration->isLoginPolicyEnforced()
            || $this->isLocalLoginAllowed()
            || trim($username) === ''
            || $password === ''
        ) {
            return $user;
        }

        return class_exists('WP_Error')
            ? new \WP_Error('municipio_entra_oidc_password_login_denied', 'WordPress password login is only available from the authorized network.')
            : $user;
    }

    public function isLocalLoginAllowed(): bool
    {
        $server = $this->server ?? $_SERVER;
        $address = isset($server['REMOTE_ADDR']) && is_string($server['REMOTE_ADDR'])
            ? $server['REMOTE_ADDR']
            : '';

        return $this->networkMatcher->matches($address, $this->configuration->localLoginNetworks());
    }

    /** @param array<string, mixed> $claims */
    private function claimsBelongToConfiguredTenant(array $claims): bool
    {
        $tenantId = $this->configuration->tenantId();

        return $tenantId !== ''
            && isset($claims['tid'])
            && is_string($claims['tid'])
            && hash_equals(strtolower($tenantId), strtolower(trim($claims['tid'])));
    }

    /** @param array<string, mixed> $claims */
    private function resolveUserGroup(array $claims): ?string
    {
        return $this->claimMapper->resolve(
            $claims,
            $this->configuration->authorizationClaim(),
            $this->configuration->userGroupMap(),
        );
    }

}
