<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer;

use InvalidArgumentException;

final readonly class TrustedIssuer
{
    /**
     * @var non-empty-string
     */
    public string $issuer;

    /**
     * @var non-empty-string
     */
    public string $clientId;

    /**
     * @var non-empty-string
     */
    public string $audience;

    /**
     * @param list<Algorithm> $allowedAlgorithms
     */
    public function __construct(
        string $issuer,
        string $clientId,
        string $audience,
        public AssertionRequirements $requirements = new AssertionRequirements(),
        public ClientAuthentication $clientAuthentication = ClientAuthentication::REQUIRED,
        public array $allowedAlgorithms = [Algorithm::ED25519],
    ) {
        if ('' === $issuer || '' === $clientId || '' === $audience) {
            throw new InvalidArgumentException('Issuer, client ID and audience must be nonempty.');
        }

        $this->issuer = $issuer;
        $this->clientId = $clientId;
        $this->audience = $audience;

        if ([] === $allowedAlgorithms) {
            throw new InvalidArgumentException('At least one allowed algorithm is required.');
        }
    }
}
