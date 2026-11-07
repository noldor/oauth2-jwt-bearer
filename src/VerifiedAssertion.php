<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer;

use DateTimeImmutable;
use Lcobucci\JWT\UnencryptedToken;

final readonly class VerifiedAssertion
{
    /**
     * @param non-empty-string $subject
     */
    public function __construct(
        public TrustedIssuer $issuer,
        public string $subject,
        public string|null $id,
        public DateTimeImmutable $expiresAt,
        public UnencryptedToken $token,
    ) {}
}
