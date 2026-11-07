<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Integration;

use DateInterval;
use LogicException;
use DomainException;
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
use League\OAuth2\Server\RequestEvent;
use Noldors\OAuth2JwtBearer\Algorithm;
use Laravel\Passport\Guards\TokenGuard;
use Psr\Http\Message\ResponseInterface;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Exceptions;
use Noldors\OAuth2JwtBearer\TrustedIssuer;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Noldors\OAuth2JwtBearer\JwtBearerGrant;
use Noldors\OAuth2JwtBearer\VerificationKey;
use Psr\Http\Message\ServerRequestInterface;
use Laravel\Passport\PassportServiceProvider;
use League\OAuth2\Server\AuthorizationServer;
use Noldors\OAuth2JwtBearer\AssertionRejected;
use Noldors\OAuth2JwtBearer\AssertionVerifier;
use PHPUnit\Framework\Attributes\DataProvider;
use Noldors\OAuth2JwtBearer\ClientAuthentication;
use Laravel\Passport\Bridge\AccessTokenRepository;
use Noldors\OAuth2JwtBearer\AssertionRequirements;
use Noldors\OAuth2JwtBearer\Contracts\KeyResolver;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\Postgres;
use Noldors\OAuth2JwtBearer\AssertionRejectionReason;
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

    private AssertionVerifier $verifier;

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
            $table->timestampsTz(6);
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
        $profile = new TrustedIssuer('crm', self::CLIENT_ID, 'mail', new AssertionRequirements(60, 3, ['iat']), ClientAuthentication::OPTIONAL);
        $this->verifier = new AssertionVerifier($keys, $this->clock, [$profile]);
        // CRM registers no raw grant on the shared Passport server.
    }

    protected function tearDown(): void
    {
        if (isset($this->application)) {
            $this->artisan('migrate:rollback', ['--force' => true]);
            Schema::dropIfExists('jwt_test_users');
        }

        Passport::$registersRoutes = true;
        Passport::tokensExpireIn(new DateInterval('P1Y'));
        Passport::tokensCan([]);
        Passport::setDefaultScope([]);
        parent::tearDown();
    }

    public function testPreparedExchangeUsesLocalUserWithoutAssertionJtiAndSupportsRevocation(): void
    {
        $this->assertFalse(
            $this->application['router']->has('passport.token'),
        );
        $body = OAuthResponse::body($this->exchange(['user_id' => '999999']));
        $this->assertEqualsWithDelta(3_600, $body['expires_in'], 1);
        $this->assertArrayNotHasKey('refresh_token', $body);
        $token = Token::query()->sole();
        $this->assertEquals($this->user->id, $token->getAttribute('user_id'));
        $this->assertSame([], $token->getAttribute('scopes'));
        $issued = OAuthResponse::token($body['access_token']);
        $this->assertSame((string) $this->user->id, $issued->claims()->get('sub'));
        $this->assertNotEmpty($issued->claims()->get('jti'));
        $request = Request::create('/private', 'GET', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $body['access_token'],
        ]);
        $guard = Auth::guard('api');
        $this->assertInstanceOf(TokenGuard::class, $guard);
        $guard->setRequest($request);
        $this->assertSame($this->user->id, $guard->user()?->getAuthIdentifier());
        $id = $token->getKey();
        $this->assertIsString($id);
        $this->application->make(AccessTokenRepository::class)->revokeAccessToken($id);
        Auth::forgetGuards();
        $guard = Auth::guard('api');
        $this->assertInstanceOf(TokenGuard::class, $guard);
        $guard->setRequest($request);
        Exceptions::fake([OAuthServerException::class]);
        $this->assertNull($guard->user());
        Exceptions::assertReportedCount(1);
    }

    public function testCrmAssertionCanBeExchangedAgainAndSharedServerKeepsNoPreparedGrant(): void
    {
        $this->exchange();
        $this->exchange();
        $this->assertSame(2, Token::query()->count());

        try {
            $this->application->make(AuthorizationServer::class)->respondToAccessTokenRequest(
                $this->request(),
                new Response(),
            );
            $this->fail(
                'The shared server must not retain the per-invocation grant.',
            );
        } catch (OAuthServerException $exception) {
            $this->assertSame('unsupported_grant_type', $exception->getErrorType());
        }
    }

    public function testPreparedScopesAndExplicitEmptyScopeUseNativePassportPolicy(): void
    {
        Passport::setDefaultScope(['read']);
        $first = OAuthResponse::body($this->exchange());
        $this->assertSame([], OAuthResponse::token($first['access_token'])->claims()->get('scopes'));
        $second = OAuthResponse::body($this->exchange(['scope' => 'read']));
        $this->assertSame(['read'], OAuthResponse::token($second['access_token'])->claims()->get('scopes'));
    }

    public function testPreparedRequestValidatesSuppliedClientCredentials(): void
    {
        $this->exchange(['client_id' => self::CLIENT_ID, 'client_secret' => 'correct-secret']);

        try {
            $this->exchange(['client_id' => self::CLIENT_ID, 'client_secret' => 'wrong']);
            $this->fail('Supplied credentials must be checked.');
        } catch (OAuthServerException $exception) {
            $this->assertSame('invalid_client', $exception->getErrorType());
        }

        $this->assertSame(1, Token::query()->count());
    }

    public function testClientMustSupportTheGrant(): void
    {
        Client::query()->whereKey(self::CLIENT_ID)->update([
            'grant_types' => \json_encode(['client_credentials'], \JSON_THROW_ON_ERROR),
        ]);

        try {
            $this->exchange();
            $this->fail('Client grant restrictions must apply.');
        } catch (OAuthServerException $exception) {
            $this->assertSame('unauthorized_client', $exception->getErrorType());
        }

        $this->assertSame(0, Token::query()->count());
    }

    public function testApplicationChecksExistingActiveUserBeforePreparingGrant(): void
    {
        $this->user->update(['active' => false]);

        try {
            $this->exchange();
            $this->fail(
                'Application user policy must reject this exchange.',
            );
        } catch (DomainException $exception) {
            $this->assertSame('No eligible local user.', $exception->getMessage());
        }

        $this->assertSame(0, Token::query()->count());
    }

    public function testSigningFailureRollsBackAndAllowsSameAssertionAgain(): void
    {
        $this->application['config']->set('passport.private_key', JwtFactory::keys('oauth')['public']);

        try {
            $this->exchange();
            $this->fail('Native signing must fail.');
        } catch (InvalidKeyProvided) {
            $this->assertSame(
                0,
                (int) Postgres::value(Postgres::connect(), 'SELECT COUNT(*) FROM passport_test.oauth_access_tokens'),
            );
        }

        $this->application['config']->set('passport.private_key', JwtFactory::keys('oauth')['private']);
        $this->application->forgetInstance(AuthorizationServer::class);
        $this->assertSame(200, $this->exchange()->getStatusCode());
    }

    public function testApplicationRechecksTimeAfterNativeResponseBeforeCommit(): void
    {
        $base = $this->application->make(AuthorizationServer::class);
        $base->getEmitter()->addListener(RequestEvent::ACCESS_TOKEN_ISSUED, function (): void {
            $this->clock->time = $this->clock->time->modify('+63 seconds');
        });

        try {
            $this->exchange();
            $this->fail(
                'The application must reject expiry after response generation.',
            );
        } catch (AssertionRejected $exception) {
            $this->assertSame(AssertionRejectionReason::EXPIRED, $exception->reason);
        }

        $this->assertSame(0, Token::query()->count());
    }

    public function testRawGrantCanUseAnAlreadyLocalSubjectAndIgnoresHttpUserId(): void
    {
        $raw = clone $this->application->make(AuthorizationServer::class);
        $raw->enableGrantType(new JwtBearerGrant($this->verifier), Passport::tokensExpireIn());
        $assertion = JwtFactory::assertion([
            'iss' => 'crm',
            'sub' => (string) $this->user->id,
            'aud' => 'mail',
            'iat' => $this->clock->now()->getTimestamp(),
            'exp' => $this->clock->now()->getTimestamp() + 60,
        ], ['alg' => 'Ed25519']);
        $request = $this->request(['assertion' => $assertion, 'user_id' => '999999'])->withAttribute('user_id', '999999');
        $response = DB::transaction(
            fn (): ResponseInterface => $raw->respondToAccessTokenRequest($request, new Response()),
        );
        $this->assertSame(
            (string) $this->user->id,
            OAuthResponse::token(
                OAuthResponse::body($response)['access_token'],
            )->claims()->get('sub'),
        );
        $this->assertEquals($this->user->id, Token::query()->sole()->getAttribute('user_id'));
    }

    /**
     * @param array{claims?: array<string, mixed>, headers?: array<string, mixed>, raw?: string, signingKey?: string} $changes
     */
    #[DataProvider('rejections')]
    public function testRawPassportPreservesStructuredReasons(array $changes, string $reason): void
    {
        $raw = clone $this->application->make(AuthorizationServer::class);
        $raw->enableGrantType(new JwtBearerGrant($this->verifier), Passport::tokensExpireIn());

        try {
            DB::transaction(
                fn (): ResponseInterface => $raw->respondToAccessTokenRequest($this->request([
                    'assertion' => RejectionCases::assertion($changes),
                ]), new Response()),
            );
            $this->fail('The raw assertion must fail.');
        } catch (OAuthServerException $exception) {
            $cause = $exception->getPrevious();
            $this->assertInstanceOf(AssertionRejected::class, $cause);
            $this->assertSame(AssertionRejectionReason::from($reason), $cause->reason);
            $this->assertSame(
                OAuthServerException::invalidGrant('The JWT assertion is invalid.')->getPayload(),
                $exception->getPayload(),
            );
        }

        $this->assertSame(0, Token::query()->count());
    }

    /**
     * @return iterable<string, array{array{claims?: array<string, mixed>, headers?: array<string, mixed>, raw?: string, signingKey?: string}, string}>
     */
    public static function rejections(): iterable
    {
        return RejectionCases::cases();
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
        $pdo = Postgres::connect();
        $pdo->exec(
            'DROP SCHEMA IF EXISTS passport_test CASCADE',
        );
        $pdo->exec('CREATE SCHEMA passport_test');
        $app['config']->set('auth.providers.users.model', PassportUser::class);
        $app['config']->set('auth.guards.api', ['driver' => 'passport', 'provider' => 'users']);
        $app['config']->set('hashing.bcrypt.rounds', 4);
    }

    /**
     * @param array<string, mixed> $parameters
     */
    private function request(array $parameters = []): ServerRequestInterface
    {
        $claims = [
            'iss' => 'crm',
            'sub' => 'external-42',
            'aud' => 'mail',
            'iat' => $this->clock->now()->getTimestamp(),
            'exp' => $this->clock->now()->getTimestamp() + 60,
        ];

        return new ServerRequest('POST', 'https://mail.example/internal/token')->withParsedBody([
            'grant_type' => JwtBearerGrant::IDENTIFIER,
            'assertion' => JwtFactory::assertion($claims, ['alg' => 'Ed25519']),
            'scope' => '',
            ...$parameters,
        ]);
    }

    /**
     * @param array<string, mixed> $parameters
     */
    private function exchange(array $parameters = []): ResponseInterface
    {
        $request = $this->request($parameters)->withAttribute('user_id', '999999');
        $base = $this->application->make(AuthorizationServer::class);

        return DB::transaction(
            function () use ($request, $base): ResponseInterface {
                $body = $request->getParsedBody();
                $this->assertIsArray($body);
                $this->assertIsString($body['assertion']);
                $verified = $this->verifier->verify($body['assertion']);
                $this->assertNull($verified->id);
                $user = PassportUser::query()->where('external_id', $verified->subject)->lockForUpdate()->first();

                if (null === $user || ! $user->active) {
                    throw new DomainException('No eligible local user.');
                }

                $server = clone $base;
                $server->enableGrantType(
                    JwtBearerGrant::forVerifiedAssertion($this->verifier, $verified, (string) $user->id),
                    Passport::tokensExpireIn(),
                );
                $response = $server->respondToAccessTokenRequest($request, new Response());
                $this->verifier->assertValidAt($verified);

                return $response;
            },
        );
    }
}
