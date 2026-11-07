<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Integration;

use Closure;
use DateInterval;
use DateTimeZone;
use LogicException;
use DomainException;
use RuntimeException;
use Nyholm\Psr7\Response;
use Laravel\Passport\Token;
use Illuminate\Http\Request;
use Laravel\Passport\Client;
use Laravel\Passport\Passport;
use Nyholm\Psr7\ServerRequest;
use Orchestra\Testbench\TestCase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Auth;
use Lcobucci\JWT\Signer\Key\InMemory;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Schema;
use Noldors\OAuth2JwtBearer\Algorithm;
use Laravel\Passport\Guards\TokenGuard;
use Psr\Http\Message\ResponseInterface;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Exceptions;
use Noldors\OAuth2JwtBearer\TrustedIssuer;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Noldors\OAuth2JwtBearer\JwtBearerGrant;
use Noldors\OAuth2JwtBearer\VerificationKey;
use Laravel\Passport\PassportServiceProvider;
use League\OAuth2\Server\AuthorizationServer;
use Noldors\OAuth2JwtBearer\AssertionRejected;
use Noldors\OAuth2JwtBearer\AssertionVerifier;
use Noldors\OAuth2JwtBearer\VerifiedAssertion;
use PHPUnit\Framework\Attributes\DataProvider;
use Noldors\OAuth2JwtBearer\ClientAuthentication;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Noldors\OAuth2JwtBearer\AssertionRequirements;
use Noldors\OAuth2JwtBearer\Contracts\KeyResolver;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\Postgres;
use Noldors\OAuth2JwtBearer\AssertionRejectionReason;
use Noldors\OAuth2JwtBearer\Contracts\SubjectResolver;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\JwtFactory;
use League\OAuth2\Server\Exception\OAuthServerException;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\MutableClock;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\PassportUser;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\OAuthResponse;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\RejectionCases;
use Noldors\OAuth2JwtBearer\Passport\JwtBearerServiceProvider;

final class PassportGrantTest extends TestCase
{
    private const string CLIENT_ID = '1d67a871-4690-4e09-a43c-6adea2a27428';

    private Application $application;

    private MutableClock $clock;

    private PassportUser $user;

    private PassportUser|null $resolvedUser = null;

    private string|null $resolvedClientId = null;

    private Closure|null $afterResolution = null;

    /**
     * @var (Closure(): void)|null test coordination in the application transaction only
     */
    private Closure|null $afterApplicationInsert = null;

    private AssertionVerifier $verifier;

    private VerifiedAssertion|null $resolvedAssertion = null;

    protected function setUp(): void
    {
        Passport::ignoreRoutes();
        parent::setUp();
        $this->application = $this->app ?? throw new LogicException('Application unavailable.');
        $this->clock = new MutableClock();
        $this->loadMigrationsFrom(
            __DIR__ . '/../../vendor/laravel/passport/database/migrations',
        );
        Schema::create('jwt_test_users', static function (Blueprint $table): void {
            $table->id();
            $table->string('external_id')->unique();
            $table->boolean('active');
            $table->timestamps();
        });
        Schema::create('assertion_uses', static function (Blueprint $table): void {
            $table->text('issuer');
            $table->text('jti');
            $table->char('token_id', 80);
            $table->timestampTz('expires_at', 6);
            $table->primary(['issuer', 'jti']);
            $table->foreign('token_id')
                ->references('id')
                ->on('oauth_access_tokens')
                ->restrictOnDelete()
                ->restrictOnUpdate();
        });
        $this->user = PassportUser::query()->create(['external_id' => 'external-42', 'active' => true]);
        Client::query()->create([
            'id' => self::CLIENT_ID,
            'name' => 'JWT CRM',
            'secret' => 'correct-secret',
            'provider' => 'users',
            'redirect_uris' => [],
            'grant_types' => [JwtBearerGrant::IDENTIFIER],
            'revoked' => false,
        ]);
        Passport::tokensExpireIn(new DateInterval('PT1H'));
        Passport::tokensCan(['read' => 'Read mail']);
        $this->bindGrant();
    }

    protected function tearDown(): void
    {
        if (isset($this->application)) {
            Schema::dropIfExists('assertion_uses');
            $this->artisan('migrate:rollback', ['--force' => true]);
            Schema::dropIfExists('jwt_test_users');
        }

        Passport::$registersRoutes = true;
        Passport::tokensExpireIn(new DateInterval('P1Y'));
        Passport::tokensCan([]);
        Passport::setDefaultScope([]);
        parent::tearDown();
    }

    public function testProgrammaticExchangeUsesPassportPersistenceGuardAndRevocation(): void
    {
        $this->assertFalse(
            $this->application['router']->has('passport.token'),
        );
        $response = $this->exchange();
        $body = OAuthResponse::body($response);
        $this->assertEqualsWithDelta(3_600, $body['expires_in'], 1);
        $this->assertArrayNotHasKey('refresh_token', $body);
        $this->assertSame(1, Token::query()->count());
        $token = Token::query()->sole();
        $this->assertEquals($this->user->id, $token->getAttribute('user_id'));
        $this->assertSame([], $token->getAttribute('scopes'));
        $this->assertSame($token->getKey(), DB::table('assertion_uses')->value('token_id'));
        $request = Request::create('/private', 'GET', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $body['access_token'],
        ]);
        $guard = Auth::guard('api');
        $this->assertInstanceOf(TokenGuard::class, $guard);
        $guard->setRequest($request);
        $this->assertSame($this->user->getKey(), $guard->user()?->getAuthIdentifier());
        $tokenId = $token->getKey();
        $this->assertIsString($tokenId);
        $this->application->make(AccessTokenRepository::class)->revokeAccessToken($tokenId);
        Auth::forgetGuards();
        $guard = Auth::guard('api');
        $this->assertInstanceOf(TokenGuard::class, $guard);
        $guard->setRequest($request);
        Exceptions::fake([OAuthServerException::class]);
        $this->assertNull($guard->user());
        Exceptions::assertReportedCount(1);
        $this->assertTrue(
            $token->fresh()?->getAttribute('revoked'),
        );
    }

    public function testExplicitEmptyScopeOverridesPassportDefault(): void
    {
        Passport::setDefaultScope(['read']);
        $body = OAuthResponse::body($this->exchange());
        $this->assertSame([], Token::query()->sole()->getAttribute('scopes'));
        $this->assertSame([], OAuthResponse::token($body['access_token'])->claims()->get('scopes'));
    }

    public function testPassportScopesAreApplied(): void
    {
        $this->exchange(['scope' => 'read']);
        $this->assertSame(['read'], Token::query()->sole()->getAttribute('scopes'));
    }

    public function testPassportValidatesSuppliedCredentials(): void
    {
        $this->exchange(['client_id' => self::CLIENT_ID, 'client_secret' => 'correct-secret']);
        $this->assertSame(1, Token::query()->count());
    }

    public function testWrongPassportSecretCannotBeIgnored(): void
    {
        try {
            $this->exchange(['client_id' => self::CLIENT_ID, 'client_secret' => 'wrong']);
            $this->fail('Credentials must be checked.');
        } catch (OAuthServerException $exception) {
            $this->assertSame('invalid_client', $exception->getErrorType());
        }

        $this->assertSame(0, Token::query()->count());
        $this->assertSame(0, DB::table('assertion_uses')->count());
    }

    public function testClientMustExplicitlySupportGrant(): void
    {
        Client::query()->whereKey(self::CLIENT_ID)->update([
            'grant_types' => \json_encode(['client_credentials'], \JSON_THROW_ON_ERROR),
        ]);

        try {
            $this->exchange();
            $this->fail(
                'Client grant restriction must be checked.',
            );
        } catch (OAuthServerException $exception) {
            $this->assertSame('unauthorized_client', $exception->getErrorType());
        }

        $this->assertSame(0, Token::query()->count());
    }

    public function testInactiveUserCannotReceiveToken(): void
    {
        $this->user->update(['active' => false]);

        try {
            $this->exchange();
            $this->fail(
                'Inactive user must be rejected by the application resolver.',
            );
        } catch (OAuthServerException $exception) {
            $this->assertSame('invalid_grant', $exception->getErrorType());
        }

        $this->assertSame(0, Token::query()->count());
        $this->assertSame(0, DB::table('assertion_uses')->count());
    }

    public function testApplicationFailureRollsBackPassportTokenAndAssertion(): void
    {
        try {
            DB::transaction(function (): void {
                $this->exchange();
                $this->user->update(['active' => false]);

                throw new RuntimeException('Injected application failure.');
            });
        } catch (RuntimeException $exception) {
            $this->assertSame('Injected application failure.', $exception->getMessage());
        }

        $this->assertSame(0, Token::query()->count());
        $this->assertSame(0, DB::table('assertion_uses')->count());
        $this->assertTrue($this->user->fresh()?->active);
        $this->assertSame(200, $this->exchange()->getStatusCode());
    }

    public function testPassportSigningFailureRollsBackAndAllowsRetry(): void
    {
        $this->application['config']->set('passport.private_key', JwtFactory::keys('oauth')['public']);

        try {
            $this->exchange();
            $this->fail('Token signing must fail.');
        } catch (InvalidKeyProvided) {
            $observer = Postgres::connect('passport-rollback-observer');
            $this->assertSame(
                0,
                (int) Postgres::value($observer, 'SELECT COUNT(*) FROM passport_test.oauth_access_tokens'),
            );
            $this->assertSame(0, (int) Postgres::value($observer, 'SELECT COUNT(*) FROM passport_test.assertion_uses'));
        }

        $this->application['config']->set('passport.private_key', JwtFactory::keys('oauth')['private']);
        $this->application->forgetInstance(AuthorizationServer::class);
        $this->assertSame(200, $this->exchange()->getStatusCode());
    }

    public function testPassportRejectsIncorrectAssertionSignature(): void
    {
        $claims = [
            'iss' => 'crm',
            'sub' => 'external-42',
            'aud' => 'mail',
            'iat' => $this->clock->now()->getTimestamp(),
            'exp' => $this->clock->now()->getTimestamp() + 60,
            'jti' => 'once',
        ];

        try {
            $this->exchange(['assertion' => JwtFactory::assertion($claims, ['alg' => 'Ed25519'], 'attacker')]);
            $this->fail(
                'An assertion signed by an untrusted key must fail.',
            );
        } catch (OAuthServerException $exception) {
            $this->assertSame('invalid_grant', $exception->getErrorType());
        }

        $this->assertSame(0, Token::query()->count());
        $this->assertSame(0, DB::table('assertion_uses')->count());
    }

    /**
     * @param array{claims?: array<string, mixed>, headers?: array<string, mixed>, raw?: string, signingKey?: string} $changes
     */
    #[DataProvider('rejections')]
    public function testPassportPreservesStructuredReason(array $changes, string $reason): void
    {
        $assertion = RejectionCases::assertion($changes);

        try {
            $this->exchange(['assertion' => $assertion]);
            $this->fail(
                'The invalid assertion must be rejected.',
            );
        } catch (OAuthServerException $exception) {
            $this->assertSame('invalid_grant', $exception->getErrorType());
            $previous = $exception->getPrevious();
            $this->assertInstanceOf(AssertionRejected::class, $previous);
            $this->assertSame(AssertionRejectionReason::from($reason), $previous->reason);
            $this->assertSame(
                OAuthServerException::invalidGrant('The JWT assertion is invalid.')->getPayload(),
                $exception->getPayload(),
            );
            $this->assertStringNotContainsString($assertion, $previous->getMessage());
        }

        $this->assertNull($this->resolvedUser);
        $this->assertNull($this->resolvedClientId);
        $this->assertSame(0, Token::query()->count());
        $this->assertSame(0, DB::table('assertion_uses')->count());
    }

    /**
     * @return iterable<string, array{array{claims?: array<string, mixed>, headers?: array<string, mixed>, raw?: string, signingKey?: string}, string}>
     */
    public static function rejections(): iterable
    {
        return RejectionCases::cases();
    }

    #[DataProvider('expiryRecheckStages')]
    public function testPostWaitExpiryPreservesApplicationIdentityContext(string $stage): void
    {
        $expire = function (): void {
            $this->clock->time = $this->clock->time->modify('+63 seconds');
        };

        if ('subject' === $stage) {
            $this->afterResolution = $expire;
        } else {
            $this->afterApplicationInsert = $expire;
        }

        try {
            $this->exchange();
            $this->fail(
                'The expired assertion must be rejected after application work.',
            );
        } catch (AssertionRejected|OAuthServerException $exception) {
            $this->assertInstanceOf(
                'subject' === $stage ? OAuthServerException::class : AssertionRejected::class,
                $exception,
            );
            $previous = $exception instanceof AssertionRejected ? $exception : $exception->getPrevious();
            $this->assertInstanceOf(AssertionRejected::class, $previous);
            $this->assertSame(AssertionRejectionReason::EXPIRED, $previous->reason);
        }

        $this->assertSame($this->user->id, $this->resolvedUser?->id);
        $this->assertSame(self::CLIENT_ID, $this->resolvedClientId);
        $observer = Postgres::connect('passport-context-rollback');
        $this->assertSame(0, (int) Postgres::value($observer, 'SELECT COUNT(*) FROM passport_test.oauth_access_tokens'));
        $this->assertSame(0, (int) Postgres::value($observer, 'SELECT COUNT(*) FROM passport_test.assertion_uses'));
    }

    #[DataProvider('expiryRecheckStages')]
    public function testApplicationExceptionsRemainUnwrappedAndRollback(string $stage): void
    {
        $failure = new DomainException('Application policy rejected the exchange.');
        $reject = static fn (): never => throw $failure;

        if ('subject' === $stage) {
            $this->afterResolution = $reject;
        } else {
            $this->afterApplicationInsert = $reject;
        }

        try {
            $this->exchange();
            $this->fail(
                'The application exception must propagate.',
            );
        } catch (DomainException $exception) {
            $this->assertSame($failure, $exception);
        }

        $this->assertSame($this->user->id, $this->resolvedUser?->id);
        $this->assertSame(self::CLIENT_ID, $this->resolvedClientId);
        $this->assertSame(0, Token::query()->count());
        $this->assertSame(0, DB::table('assertion_uses')->count());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function expiryRecheckStages(): iterable
    {
        yield 'after user resolution' => ['subject'];

        yield 'after application replay insert' => ['application_insert'];
    }

    protected function getPackageProviders($app): array
    {
        return [PassportServiceProvider::class, JwtBearerServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:' . \base64_encode(\str_repeat('k', 32)));
        $app['config']->set('passport.private_key', JwtFactory::keys('oauth')['private']);
        $app['config']->set('passport.public_key', JwtFactory::keys('oauth')['public']);
        $app['config']->set('database.default', 'pgsql');
        $app['config']->set('database.connections.pgsql', [
            'driver' => 'pgsql',
            'host' => \getenv('DB_HOST') ?: 'postgres',
            'port' => \getenv('DB_PORT') ?: '5432',
            'database' => \getenv('DB_DATABASE') ?: 'oauth2_jwt_bearer_testing',
            'username' => \getenv('DB_USERNAME') ?: 'packages',
            'password' => \getenv('DB_PASSWORD') ?: '',
            'charset' => 'utf8',
            'prefix' => '',
            'search_path' => 'passport_test',
            'sslmode' => 'prefer',
        ]);
        // Separate schema from the raw League fixtures and concurrent workers.
        $pdo = \Noldors\OAuth2JwtBearer\Tests\Fixtures\Postgres::connect();
        $pdo->exec(
            'DROP SCHEMA IF EXISTS passport_test CASCADE',
        );
        $pdo->exec('CREATE SCHEMA passport_test');
        $app['config']->set('auth.providers.users.model', PassportUser::class);
        $app['config']->set('auth.guards.api', ['driver' => 'passport', 'provider' => 'users']);
        $app['config']->set('hashing.bcrypt.rounds', 4);
    }

    private function bindGrant(): void
    {
        $keys = new class () implements KeyResolver {
            public function resolve(string $issuer, string $keyId): VerificationKey|null
            {
                return 'crm' === $issuer && 'current' === $keyId
                    ? new VerificationKey(Algorithm::ED25519, InMemory::plainText(
                        JwtFactory::keys('ed25519:crm')['public'],
                    ))
                    : null;
            }
        };
        $onResolved = function (VerifiedAssertion $assertion, PassportUser $user): void {
            $this->resolvedAssertion = $assertion;
            $this->resolvedUser = $user;
            $this->resolvedClientId = $assertion->issuer->clientId;
            ($this->afterResolution ?? static function (): void {})();
        };
        $subjects = new class ($onResolved) implements SubjectResolver {
            /**
             * @param Closure(VerifiedAssertion, PassportUser): void $onResolved
             */
            public function __construct(
                private readonly Closure $onResolved,
            ) {}

            public function resolve(VerifiedAssertion $assertion): string
            {
                $user = PassportUser::query()->where('external_id', $assertion->subject)->lockForUpdate()->first();

                if (null === $user || ! $user->active) {
                    throw new AssertionRejected('No eligible user.');
                }

                ($this->onResolved)($assertion, $user);

                return (string) $user->id;
            }
        };
        $issuer = new TrustedIssuer('crm', self::CLIENT_ID, 'mail', new AssertionRequirements(60, 3), ClientAuthentication::OPTIONAL);
        $this->verifier = new AssertionVerifier($keys, $this->clock, [$issuer]);
        $grant = new JwtBearerGrant($this->verifier, $subjects);
        $this->application->bind(JwtBearerGrant::class, static fn (): JwtBearerGrant => $grant);
    }

    /**
     * @param array<string, mixed> $parameters
     */
    private function exchange(array $parameters = []): ResponseInterface
    {
        $this->resolvedAssertion = null;
        $this->resolvedUser = null;
        $this->resolvedClientId = null;
        $claims = [
            'iss' => 'crm',
            'sub' => 'external-42',
            'aud' => 'mail',
            'iat' => $this->clock->now()->getTimestamp(),
            'exp' => $this->clock->now()->getTimestamp() + 60,
            'jti' => 'once',
        ];
        $request = new ServerRequest('POST', 'https://mail.example/internal/token')->withParsedBody([
            'grant_type' => JwtBearerGrant::IDENTIFIER,
            'assertion' => JwtFactory::assertion($claims, ['alg' => 'Ed25519']),
            'scope' => '',
            ...$parameters,
        ]);

        return DB::transaction(
            function () use ($request): ResponseInterface {
                $response = $this->application->make(AuthorizationServer::class)
                    ->respondToAccessTokenRequest($request, new Response());
                $assertion = $this->resolvedAssertion ?? throw new LogicException('The application must retain the verified assertion.');
                $body = OAuthResponse::body($response);
                $tokenId = OAuthResponse::token($body['access_token'])->claims()->get('jti');
                $this->assertIsString($tokenId);
                $validUntil = $assertion->expiresAt->add(
                    new DateInterval('PT' . $assertion->issuer->requirements->leewaySeconds . 'S'),
                );
                $inserted = DB::table('assertion_uses')->insertOrIgnore([
                    'issuer' => $assertion->issuer->issuer,
                    'jti' => $assertion->id,
                    'token_id' => $tokenId,
                    'expires_at' => $validUntil->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\\TH:i:s.uP'),
                ]);

                if (1 !== $inserted) {
                    throw new DomainException('Application replay rejected.');
                }

                ($this->afterApplicationInsert ?? static function (): void {})();
                $this->verifier->assertValidAt($assertion);

                return $response;
            },
        );
    }
}
