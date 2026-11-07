<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Fixtures;

final class RejectionCases
{
    /**
     * @return iterable<string, array{array{claims?: array<string, mixed>, headers?: array<string, mixed>, raw?: string, signingKey?: string}, string}>
     */
    public static function cases(): iterable
    {
        yield 'malformed' => [['raw' => 'not-a-jwt'], 'invalid_assertion'];

        yield 'unknown issuer' => [['claims' => ['iss' => 'untrusted']], 'claims_invalid'];

        yield 'missing kid' => [['headers' => ['kid' => null]], 'key_unknown'];

        yield 'unknown kid' => [['headers' => ['kid' => 'untrusted']], 'key_unknown'];

        yield 'disallowed algorithm' => [['headers' => ['alg' => 'RS256']], 'algorithm_invalid'];

        yield 'invalid signature' => [['signingKey' => 'attacker'], 'signature_invalid'];

        yield 'invalid audience' => [['claims' => ['aud' => 'elsewhere']], 'claims_invalid'];

        yield 'missing jti' => [['claims' => ['jti' => null]], 'claims_invalid'];

        yield 'invalid temporal type' => [['claims' => ['exp' => 'never']], 'claims_invalid'];

        yield 'invalid lifetime' => [['claims' => ['exp' => 1_794_052_861]], 'claims_invalid'];

        yield 'expired' => [['claims' => ['iat' => 1_794_052_740, 'exp' => 1_794_052_797]], 'expired'];

        yield 'future iat' => [['claims' => ['iat' => 1_794_052_804]], 'not_yet_valid'];

        yield 'future nbf' => [['claims' => ['nbf' => 1_794_052_804]], 'not_yet_valid'];
    }

    /**
     * @param array{claims?: array<string, mixed>, headers?: array<string, mixed>, raw?: string, signingKey?: string} $changes
     */
    public static function assertion(array $changes): string
    {
        $claims = [
            'iss' => 'crm',
            'sub' => 'external-42',
            'aud' => 'mail',
            'iat' => 1_794_052_800,
            'exp' => 1_794_052_860,
            'jti' => 'once',
        ];

        return $changes['raw'] ?? JwtFactory::assertion(\array_replace($claims, $changes['claims'] ?? []), [
            'alg' => 'Ed25519',
            ...($changes['headers'] ?? []),
        ], $changes['signingKey'] ?? 'crm');
    }
}
