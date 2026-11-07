<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Passport;

use Laravel\Passport\Passport;
use Illuminate\Support\ServiceProvider;
use Noldors\OAuth2JwtBearer\JwtBearerGrant;
use League\OAuth2\Server\AuthorizationServer;
use Illuminate\Contracts\Foundation\Application;

final class JwtBearerServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->callAfterResolving(
            AuthorizationServer::class,
            static function (AuthorizationServer $server, Application $app): void {
                if ($app->bound(JwtBearerGrant::class)) {
                    $server->enableGrantType($app->make(JwtBearerGrant::class), Passport::tokensExpireIn());
                }
            },
        );
    }
}
