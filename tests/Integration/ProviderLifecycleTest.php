<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Integration;

use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use League\OAuth2\Server\CryptKey;
use Illuminate\Container\Container;
use Illuminate\Foundation\Application;
use Noldors\OAuth2JwtBearer\TrustedIssuer;
use Noldors\OAuth2JwtBearer\JwtBearerGrant;
use League\OAuth2\Server\AuthorizationServer;
use Noldors\OAuth2JwtBearer\AssertionVerifier;
use PHPUnit\Framework\Attributes\DataProvider;
use Noldors\OAuth2JwtBearer\Contracts\KeyResolver;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\JwtFactory;
use League\OAuth2\Server\Exception\OAuthServerException;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\MutableClock;
use Noldors\OAuth2JwtBearer\Passport\JwtBearerServiceProvider;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;

final class ProviderLifecycleTest extends TestCase
{
    #[DataProvider('serverResolutionOrders')]
    public function testRegistersBoundRawGrantInEitherResolutionOrder(bool $alreadyResolved): void
    {
        $previous = Container::getInstance();
        $app = new Application(\sys_get_temp_dir());

        try {
            $server = new AuthorizationServer(
                $this->createStub(ClientRepositoryInterface::class),
                $this->createStub(AccessTokenRepositoryInterface::class),
                $this->createStub(ScopeRepositoryInterface::class),
                new CryptKey(JwtFactory::keys('oauth')['private'], keyPermissionsCheck: false),
                'test-encryption-key',
            );
            $grant = new JwtBearerGrant(
                new AssertionVerifier($this->createStub(KeyResolver::class), new MutableClock(), [
                    new TrustedIssuer('crm', 'client', 'mail'),
                ]),
            );
            $app->bind(JwtBearerGrant::class, static fn (): JwtBearerGrant => $grant);
            $app->singleton(AuthorizationServer::class, static fn (): AuthorizationServer => $server);

            if ($alreadyResolved) {
                $this->assertSame($server, $app->make(AuthorizationServer::class));
            }

            new JwtBearerServiceProvider($app)->boot();
            $request = new ServerRequest('POST', 'https://mail.example/internal/token')->withParsedBody([
                'grant_type' => JwtBearerGrant::IDENTIFIER,
            ]);

            try {
                $app->make(AuthorizationServer::class)->respondToAccessTokenRequest($request, new Response());
                $this->fail(
                    'The enabled JWT grant must report its missing assertion.',
                );
            } catch (OAuthServerException $exception) {
                $this->assertSame('invalid_request', $exception->getErrorType());
            }
        } finally {
            Container::setInstance($previous);
        }
    }

    /**
     * @return iterable<string, array{bool}>
     */
    public static function serverResolutionOrders(): iterable
    {
        yield 'server already resolved' => [true];

        yield 'server resolved after provider boot' => [false];
    }
}
