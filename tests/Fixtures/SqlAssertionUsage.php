<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Fixtures;

use PDO;
use Closure;
use DateInterval;
use LogicException;
use Noldors\OAuth2JwtBearer\AssertionRejected;
use Noldors\OAuth2JwtBearer\VerifiedAssertion;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use Noldors\OAuth2JwtBearer\Contracts\AssertionUsageRepository;

final class SqlAssertionUsage implements AssertionUsageRepository
{
    public Closure|null $afterRecord = null;

    public function __construct(
        private readonly PDO $connection,
    ) {}

    public function record(VerifiedAssertion $assertion, AccessTokenEntityInterface $token): void
    {
        if (! $this->connection->inTransaction()) {
            throw new LogicException('The application must open the issuance transaction.');
        }

        $statement = $this->connection->prepare(
            'INSERT INTO assertion_uses (issuer, jti, token_id, expires_at) VALUES (?, ?, ?, ?) ON CONFLICT (issuer, jti) DO NOTHING',
        );
        $expiresAt = $assertion->expiresAt->add(
            new DateInterval('PT' . $assertion->issuer->requirements->leewaySeconds . 'S'),
        );
        $statement->execute([
            $assertion->issuer->issuer,
            $assertion->id,
            $token->getIdentifier(),
            $expiresAt->format('Y-m-d H:i:s.uP'),
        ]);

        if ($statement->rowCount() !== 1) {
            throw new AssertionRejected('Assertion has already been consumed.');
        }

        ($this->afterRecord ?? static function (): void {})();
    }
}
