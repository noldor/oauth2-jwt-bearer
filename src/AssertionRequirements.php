<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer;

use InvalidArgumentException;
use Lcobucci\JWT\Validation\Constraint;

final readonly class AssertionRequirements
{
    /**
     * @param list<non-empty-string> $requiredClaims
     * @param list<Constraint> $constraints additional Lcobucci constraints applied after signature verification
     */
    public function __construct(
        public int $maxLifetimeSeconds = 60,
        public int $leewaySeconds = 0,
        public array $requiredClaims = ['iat', 'jti'],
        public array $constraints = [],
    ) {
        if (1 > $maxLifetimeSeconds || 0 > $leewaySeconds) {
            throw new InvalidArgumentException('Assertion lifetime must be positive and leeway nonnegative.');
        }
    }
}
