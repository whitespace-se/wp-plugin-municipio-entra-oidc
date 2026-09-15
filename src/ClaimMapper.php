<?php

declare(strict_types=1);

namespace Whitespace\MunicipioEntraOidc;

final class ClaimMapper
{
    /**
     * Mapping order is priority order: the first matching claim wins.
     *
     * @param array<string, mixed> $claims
     * @param array<mixed, mixed>  $mapping
     */
    public function resolve(array $claims, string $claimName, array $mapping): ?string
    {
        if ($claimName === '' || !array_key_exists($claimName, $claims)) {
            return null;
        }

        $rawValues = is_array($claims[$claimName]) ? $claims[$claimName] : [$claims[$claimName]];
        $values = [];

        foreach ($rawValues as $value) {
            if (is_string($value) && trim($value) !== '') {
                $values[] = trim($value);
            }
        }

        foreach ($mapping as $claimValue => $userGroup) {
            if (
                is_string($claimValue)
                && is_string($userGroup)
                && trim($userGroup) !== ''
                && in_array($claimValue, $values, true)
            ) {
                return trim($userGroup);
            }
        }

        return null;
    }
}
