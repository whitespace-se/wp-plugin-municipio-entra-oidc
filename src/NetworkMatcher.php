<?php

declare(strict_types=1);

namespace Whitespace\MunicipioEntraOidc;

final class NetworkMatcher
{
    /**
     * @param array<int, mixed> $networks
     */
    public function matches(string $address, array $networks): bool
    {
        $packedAddress = @inet_pton(trim($address));

        if ($packedAddress === false) {
            return false;
        }

        foreach ($networks as $network) {
            if (!is_string($network) || trim($network) === '') {
                continue;
            }

            if ($this->matchesNetwork($packedAddress, trim($network))) {
                return true;
            }
        }

        return false;
    }

    private function matchesNetwork(string $packedAddress, string $network): bool
    {
        [$networkAddress, $prefix] = array_pad(explode('/', $network, 2), 2, null);
        $packedNetwork = @inet_pton($networkAddress);

        if ($packedNetwork === false || strlen($packedAddress) !== strlen($packedNetwork)) {
            return false;
        }

        $maximumPrefix = strlen($packedNetwork) * 8;

        if ($prefix === null) {
            $prefixLength = $maximumPrefix;
        } elseif ($prefix !== '' && ctype_digit($prefix)) {
            $prefixLength = (int) $prefix;
        } else {
            return false;
        }

        if ($prefixLength < 0 || $prefixLength > $maximumPrefix) {
            return false;
        }

        $wholeBytes = intdiv($prefixLength, 8);
        $remainingBits = $prefixLength % 8;

        if ($wholeBytes > 0 && substr($packedAddress, 0, $wholeBytes) !== substr($packedNetwork, 0, $wholeBytes)) {
            return false;
        }

        if ($remainingBits === 0) {
            return true;
        }

        $mask = (0xff << (8 - $remainingBits)) & 0xff;

        return (ord($packedAddress[$wholeBytes]) & $mask) === (ord($packedNetwork[$wholeBytes]) & $mask);
    }
}
