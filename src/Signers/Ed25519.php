<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Signers;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Eddsa;

/**
 * @internal adapts the RFC 9864 identifier; cryptography belongs to lcobucci/jwt
 */
final class Ed25519 implements Signer
{
    public function algorithmId(): string
    {
        return 'Ed25519';
    }

    public function sign(string $payload, Key $key): string
    {
        return new Eddsa()->sign($payload, $key);
    }

    public function verify(string $expected, string $payload, Key $key): bool
    {
        return new Eddsa()->verify($expected, $payload, $key);
    }
}
