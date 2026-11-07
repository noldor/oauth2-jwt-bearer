<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Fixtures;

use PDO;
use Closure;
use RuntimeException;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;

final class LeagueTokens implements AccessTokenRepositoryInterface
{
    public bool $failPersistence = false;

    /**
     * @var (Closure(): void)|null
     */
    public Closure|null $afterPersist = null;

    public function __construct(
        private readonly PDO $connection,
    ) {}

    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, string|null $userIdentifier = null): AccessTokenEntityInterface
    {
        $token = new LeagueAccessToken();
        $token->setClient($clientEntity);

        if (null !== $userIdentifier && '' !== $userIdentifier) {
            $token->setUserIdentifier($userIdentifier);
        }

        foreach ($scopes as $scope) {
            $token->addScope($scope);
        }

        return $token;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        $statement = $this->connection->prepare(
            'INSERT INTO league_tokens (id, user_id, client_id, scopes) VALUES (?, ?, ?, ?)',
        );
        $scopes = \array_map(static fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(), $accessTokenEntity->getScopes());
        $statement->execute([
            $accessTokenEntity->getIdentifier(),
            $accessTokenEntity->getUserIdentifier(),
            $accessTokenEntity->getClient()->getIdentifier(),
            \json_encode($scopes, \JSON_THROW_ON_ERROR),
        ]);

        if ($this->failPersistence) {
            throw new RuntimeException('Injected persistence failure.');
        }

        ($this->afterPersist ?? static function (): void {})();
    }

    public function revokeAccessToken(string $tokenId): void
    {
        $statement = $this->connection->prepare(
            'UPDATE league_tokens SET revoked = TRUE WHERE id = ?',
        );
        $statement->execute([$tokenId]);
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        $statement = $this->connection->prepare(
            'SELECT revoked FROM league_tokens WHERE id = ?',
        );
        $statement->execute([$tokenId]);

        return $statement->fetchColumn() !== false;
    }
}
