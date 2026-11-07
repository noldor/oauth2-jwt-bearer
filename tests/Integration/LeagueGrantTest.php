<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Integration;

use PDO;
use RuntimeException;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use PHPUnit\Framework\Attributes\DataProvider;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\Postgres;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\JwtFactory;
use League\OAuth2\Server\Exception\OAuthServerException;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\OAuthResponse;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\LeagueEnvironment;

final class LeagueGrantTest extends TestCase
{
    private PDO $connection;

    private LeagueEnvironment $environment;

    protected function setUp(): void
    {
        $this->connection = Postgres::connect();
        Postgres::createSchema($this->connection);
        $this->environment = new LeagueEnvironment($this->connection);
    }

    public function testIssuesStandardLeagueTokenWithMappedUserAndScopes(): void
    {
        $response = $this->environment->exchange(
            $this->environment->request(['scope' => 'read write']),
        );
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        $body = OAuthResponse::body($response);
        $this->assertSame('Bearer', $body['token_type']);
        $this->assertEqualsWithDelta(3_600, $body['expires_in'], 1);
        $this->assertArrayNotHasKey('refresh_token', $body);
        $token = OAuthResponse::token($body['access_token']);
        $this->assertSame('internal-7', $token->claims()->get('sub'));
        $this->assertSame(['oauth-client'], $token->claims()->get('aud'));
        $this->assertSame(['read', 'write'], $token->claims()->get('scopes'));
        $this->assertSame(
            $token->claims()->get('jti'),
            Postgres::value($this->connection, 'SELECT token_id FROM assertion_uses'),
        );
        $this->assertSame(1, (int) Postgres::value($this->connection, 'SELECT COUNT(*) FROM league_tokens'));
    }

    public function testExplicitEmptyScopeOverridesServerDefault(): void
    {
        $this->environment->defaultScope = 'read';
        $response = $this->environment->exchange(
            $this->environment->request(['scope' => '']),
        );
        $body = OAuthResponse::body($response);
        $this->assertSame([], OAuthResponse::token($body['access_token'])->claims()->get('scopes'));
    }

    public function testOmittedScopeUsesServerDefault(): void
    {
        $this->environment->defaultScope = 'read';
        $response = $this->environment->exchange($this->environment->request());
        $body = OAuthResponse::body($response);
        $this->assertSame(['read'], OAuthResponse::token($body['access_token'])->claims()->get('scopes'));
    }

    public function testScopeRepositoryFinalizesScopes(): void
    {
        $this->environment->finalScopes = ['read'];
        $response = $this->environment->exchange(
            $this->environment->request(['scope' => 'read write']),
        );
        $body = OAuthResponse::body($response);
        $token = OAuthResponse::token($body['access_token']);
        $this->assertSame(['read'], $token->claims()->get('scopes'));
    }

    public function testAcceptsValidatedFormCredentials(): void
    {
        $this->environment->requireAuthentication = true;
        $this->assertSame(200, $this->environment->exchange($this->environment->request([
            'client_id' => 'oauth-client',
            'client_secret' => 'correct-secret',
        ]))->getStatusCode());
    }

    public function testAcceptsValidatedBasicCredentials(): void
    {
        $this->environment->requireAuthentication = true;
        $request = $this->environment->request()->withHeader(
            'Authorization',
            'Basic ' . \base64_encode('oauth-client:correct-secret'),
        );
        $this->assertSame(200, $this->environment->exchange($request)->getStatusCode());
    }

    /**
     * @param array<string, mixed> $body
     */
    #[DataProvider('invalidRequests')]
    public function testStandardErrorsLeaveNoTokenOrUsage(array $body, string $expectedError, string|null $header = null): void
    {
        $request = $this->environment->request($body);

        if (null !== $header) {
            $request = $request->withHeader('Authorization', $header);
        }

        try {
            $this->environment->exchange($request);
            $this->fail('The exchange must fail.');
        } catch (OAuthServerException $exception) {
            $this->assertSame($expectedError, $exception->getErrorType());
            $error = \json_decode((string) $exception->generateHttpResponse(new Response())->getBody(), true, flags: \JSON_THROW_ON_ERROR);
            $this->assertIsArray($error);
            $this->assertSame($expectedError, $error['error']);
        }

        $this->assertEmptyDatabase();
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string, 2?: string}>
     */
    public static function invalidRequests(): iterable
    {
        yield 'missing assertion' => [['assertion' => null], 'invalid_request'];

        yield 'malformed assertion' => [['assertion' => 'not-a-jwt'], 'invalid_grant'];

        yield 'assertion array' => [['assertion' => ['bad']], 'invalid_request'];

        yield 'unknown scope' => [['scope' => 'admin'], 'invalid_scope'];

        yield 'array scope' => [['scope' => ['read']], 'invalid_request'];

        yield 'bad secret even optional' => [
            ['client_id' => 'oauth-client', 'client_secret' => 'wrong'],
            'invalid_client',
        ];

        yield 'missing secret' => [['client_id' => 'oauth-client'], 'invalid_client'];

        yield 'client binding mismatch' => [
            ['client_id' => 'other-client', 'client_secret' => 'correct-secret'],
            'invalid_client',
        ];

        yield 'unknown client' => [['client_id' => 'missing', 'client_secret' => 'correct-secret'], 'invalid_client'];

        yield 'secret without id' => [['client_secret' => 'correct-secret'], 'invalid_request'];

        yield 'client assertion unsupported' => [['client_assertion' => 'jwt'], 'invalid_request'];

        yield 'malformed basic' => [[], 'invalid_client', 'Basic invalid'];

        yield 'unsupported authentication' => [[], 'invalid_client', 'Bearer unrelated'];

        yield 'multiple auth mechanisms' => [
            ['client_id' => 'oauth-client', 'client_secret' => 'correct-secret'],
            'invalid_client',
            'Basic ' . \base64_encode('oauth-client:wrong'),
        ];
    }

    public function testRequiredClientAuthenticationCannotBeOmitted(): void
    {
        $this->environment->requireAuthentication = true;
        $this->expectException(OAuthServerException::class);

        try {
            $this->environment->exchange($this->environment->request());
        } finally {
            $this->assertEmptyDatabase();
        }
    }

    public function testReplayCannotIssueAnotherToken(): void
    {
        $request = $this->environment->request();
        $this->environment->exchange($request);

        try {
            $this->environment->exchange($request);
            $this->fail('Replay must fail.');
        } catch (OAuthServerException $exception) {
            $this->assertSame('invalid_grant', $exception->getErrorType());
        }

        $this->assertSame(1, (int) Postgres::value($this->connection, 'SELECT COUNT(*) FROM league_tokens'));
        $this->assertSame(1, (int) Postgres::value($this->connection, 'SELECT COUNT(*) FROM assertion_uses'));
    }

    public function testRechecksExpirationAfterUserResolution(): void
    {
        $this->environment->resolveUser = function (): string {
            $this->environment->clock->time = $this->environment->clock->time->modify('+63 seconds');

            return 'internal-7';
        };
        $this->expectException(OAuthServerException::class);

        try {
            $this->environment->exchange($this->environment->request());
        } finally {
            $this->assertEmptyDatabase();
        }
    }

    public function testRechecksExpirationAfterUsageRecording(): void
    {
        $this->environment->usage->afterRecord = function (): void {
            $this->environment->clock->time = $this->environment->clock->time->modify('+63 seconds');
        };
        $this->expectException(OAuthServerException::class);

        try {
            $this->environment->exchange($this->environment->request());
        } finally {
            $this->assertEmptyDatabase();
        }
    }

    public function testPersistenceFailureRollsBackAndAllowsRetry(): void
    {
        $request = $this->environment->request();
        $this->environment->tokens->failPersistence = true;

        try {
            $this->environment->exchange($request);
            $this->fail('Persistence must fail.');
        } catch (RuntimeException $exception) {
            $this->assertSame('Injected persistence failure.', $exception->getMessage());
        }

        $this->assertEmptyDatabase();
        $this->environment->tokens->failPersistence = false;
        $this->assertSame(200, $this->environment->exchange($request)->getStatusCode());
    }

    public function testSigningFailureRollsBackAndAllowsRetry(): void
    {
        $request = $this->environment->request();
        $this->environment->signingKey = JwtFactory::keys('oauth')['public'];

        try {
            $this->environment->exchange($request);
            $this->fail('Signing must fail.');
        } catch (InvalidKeyProvided) {
            $this->assertEmptyDatabase();
        }

        $this->environment->signingKey = null;
        $this->assertSame(200, $this->environment->exchange($request)->getStatusCode());
    }

    public function testUnsupportedGrantIsHandledByLeague(): void
    {
        $request = new ServerRequest('POST', 'https://oauth.example/token')->withParsedBody(['grant_type' => 'wrong']);

        try {
            $this->environment->exchange($request);
            $this->fail('Grant must not be accepted.');
        } catch (OAuthServerException $exception) {
            $this->assertSame('unsupported_grant_type', $exception->getErrorType());
        }

        $this->assertEmptyDatabase();
    }

    private function assertEmptyDatabase(): void
    {
        // This independent connection observes durable rollback before retry.
        $observer = Postgres::connect('rollback-observer');
        $this->assertSame(0, (int) Postgres::value($observer, 'SELECT COUNT(*) FROM league_tokens'));
        $this->assertSame(0, (int) Postgres::value($observer, 'SELECT COUNT(*) FROM assertion_uses'));
    }
}
