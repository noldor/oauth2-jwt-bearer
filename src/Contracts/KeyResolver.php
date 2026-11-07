<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Contracts;

use Noldors\OAuth2JwtBearer\VerificationKey;

interface KeyResolver
{
    /**
     * Return a locally trusted public key or null. Never fetch a URL supplied by the JWT.
     */
    public function resolve(string $issuer, string $keyId): VerificationKey|null;
}
