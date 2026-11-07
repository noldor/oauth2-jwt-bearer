<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Fixtures;

use PDO;
use Closure;
use Throwable;
use DateInterval;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use League\OAuth2\Server\CryptKey;
use Lcobucci\JWT\Signer\Key\InMemory;
use Noldors\OAuth2JwtBearer\Algorithm;
use Psr\Http\Message\ResponseInterface;
use Noldors\OAuth2JwtBearer\TrustedIssuer;
use Noldors\OAuth2JwtBearer\JwtBearerGrant;
use Noldors\OAuth2JwtBearer\VerificationKey;
use Psr\Http\Message\ServerRequestInterface;
use League\OAuth2\Server\AuthorizationServer;
use Noldors\OAuth2JwtBearer\AssertionRejected;
use Noldors\OAuth2JwtBearer\AssertionVerifier;
use Noldors\OAuth2JwtBearer\VerifiedAssertion;
use Noldors\OAuth2JwtBearer\ClientAuthentication;
use Noldors\OAuth2JwtBearer\AssertionRequirements;
use Noldors\OAuth2JwtBearer\Contracts\KeyResolver;
use Noldors\OAuth2JwtBearer\Contracts\SubjectResolver;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;

final class LeagueEnvironment
{
    public readonly MutableClock $clock;

    public readonly SqlAssertionUsage $usage;

    public readonly LeagueTokens $tokens;

    /**
     * @var (Closure(VerifiedAssertion): string)|null
     */
    public Closure|null $resolveUser = null;

    public bool $requireAuthentication = false;

    public string $defaultScope = '';

    public string|null $signingKey = null;

    /**
     * @var non-empty-string
     */
    public string $verificationKey;

    /**
     * @var list<non-empty-string>|null
     */
    public array|null $finalScopes = null;

    public function __construct(
        public readonly PDO $connection,
    ) {
        $this->clock = new MutableClock();
        $this->usage = new SqlAssertionUsage($connection);
        $this->tokens = new LeagueTokens($connection);
        $this->verificationKey = JwtFactory::keys('ed25519:crm')['public'];
    }

    public function server(): AuthorizationServer
    {
        $clients = new class () implements ClientRepositoryInterface {
            public function getClientEntity(string $clientIdentifier): ClientEntityInterface|null
            {
                return \in_array($clientIdentifier, ['oauth-client', 'other-client'], true)
                    ? new LeagueClient($clientIdentifier)
                    : null;
            }

            public function validateClient(string $clientIdentifier, string|null $clientSecret, string|null $grantType): bool
            {
                return 'correct-secret' === $clientSecret;
            }
        };
        $scopes = new class ($this) implements ScopeRepositoryInterface {
            public function __construct(
                private readonly LeagueEnvironment $environment,
            ) {}

            public function getScopeEntityByIdentifier(string $identifier): ScopeEntityInterface|null
            {
                return \in_array($identifier, ['read', 'write'], true) ? new LeagueScope($identifier) : null;
            }

            public function finalizeScopes(array $scopes, string $grantType, ClientEntityInterface $clientEntity, string|null $userIdentifier = null, string|null $authCodeId = null): array
            {
                return null === $this->environment->finalScopes
                    ? $scopes
                    : \array_map(static fn ($scope): LeagueScope => new LeagueScope($scope), $this->environment->finalScopes);
            }
        };
        $keys = new class ($this->verificationKey) implements KeyResolver {
            /**
             * @param non-empty-string $key
             */
            public function __construct(
                private readonly string $key,
            ) {}

            public function resolve(string $issuer, string $keyId): VerificationKey|null
            {
                return 'crm' === $issuer && 'current' === $keyId
                    ? new VerificationKey(Algorithm::ED25519, InMemory::plainText($this->key))
                    : null;
            }
        };
        $subjects = new class ($this) implements SubjectResolver {
            public function __construct(
                private readonly LeagueEnvironment $environment,
            ) {}

            public function resolve(VerifiedAssertion $assertion): string
            {
                if (null !== $this->environment->resolveUser) {
                    return ($this->environment->resolveUser)($assertion);
                }

                if ('external-42' !== $assertion->subject) {
                    throw new AssertionRejected('No eligible local user.');
                }

                return 'internal-7';
            }
        };
        $issuer = new TrustedIssuer('crm', 'oauth-client', 'mail', new AssertionRequirements(60, 3), $this->requireAuthentication ? ClientAuthentication::REQUIRED : ClientAuthentication::OPTIONAL);
        $grant = new JwtBearerGrant(new AssertionVerifier($keys, $this->clock, [$issuer]), $subjects, $this->usage);
        $server = new AuthorizationServer($clients, $this->tokens, $scopes, new CryptKey($this->signingKey ?? JwtFactory::keys('oauth')['private'], keyPermissionsCheck: false), 'test-encryption-key');
        $server->setDefaultScope($this->defaultScope);
        $server->enableGrantType($grant, new DateInterval('PT1H'));

        return $server;
    }

    /**
     * @param array<string, mixed> $body
     */
    public function request(array $body = []): ServerRequestInterface
    {
        $claims = [
            'iss' => 'crm',
            'sub' => 'external-42',
            'aud' => 'mail',
            'iat' => $this->clock->now()->getTimestamp(),
            'exp' => $this->clock->now()->getTimestamp() + 60,
            'jti' => 'once',
        ];

        return new ServerRequest('POST', 'https://oauth.example/token')->withParsedBody([
            'grant_type' => JwtBearerGrant::IDENTIFIER,
            'assertion' => JwtFactory::assertion($claims, ['alg' => 'Ed25519']),
            ...$body,
        ]);
    }

    public function exchange(ServerRequestInterface $request): ResponseInterface
    {
        $this->connection->beginTransaction();

        try {
            $response = $this->server()->respondToAccessTokenRequest($request, new Response());
            $this->connection->commit();

            return $response;
        } catch (Throwable $exception) {
            $this->connection->rollBack();

            throw $exception;
        }
    }
}
