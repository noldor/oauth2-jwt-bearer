# Laravel Passport integration

The package uses native Passport clients, AuthorizationServer, token repository, scopes, bearer guard and revocation. No internals are copied or patched. The optional auto-discovered provider enables a raw grant **only if the application explicitly binds `JwtBearerGrant`**, with normal `Passport::tokensExpireIn()` TTL. Both server-resolution orders are supported.

## External CRM subject: bind only the verifier

CRM `sub` is an external ID. Do not bind a raw `JwtBearerGrant` or register it on the shared server. Bind the configured verifier, trusted `KeyResolver` and PSR Clock in the application's normal provider:

```php
use Noldors\OAuth2JwtBearer\{
    AssertionRequirements, AssertionVerifier, ClientAuthentication, TrustedIssuer,
};

$this->app->singleton(AssertionVerifier::class, fn ($app) => new AssertionVerifier(
    $app->make(\Noldors\OAuth2JwtBearer\Contracts\KeyResolver::class),
    $app->make(\Psr\Clock\ClockInterface::class),
    [new TrustedIssuer(
        issuer: config('crm.issuer'),
        clientId: config('crm.oauth_client_id'),
        audience: config('crm.audience'),
        requirements: new AssertionRequirements(60, 3, ['iat']),
        clientAuthentication: ClientAuthentication::OPTIONAL,
    )],
));
```

Default algorithm is `Ed25519`. CRM requires `iat` and `exp`, no assertion `jti` or one-time storage. Native access-token `jti` remains unchanged. Set native TTL during setup with `Passport::tokensExpireIn(new DateInterval('PT1H'))`.

## Programmatic issuance

GraphQL accepts only assertion; its application operation constructs OAuth parameters. Here `$verifier` and the ordinary `$authorizationServer` are injected; `User` is the existing application model:

```php
use Illuminate\Support\Facades\DB;
use Laravel\Passport\Passport;
use Nyholm\Psr7\{Response, ServerRequest};
use Noldors\OAuth2JwtBearer\JwtBearerGrant;

$request = (new ServerRequest('POST', 'https://mail.example/internal/exchange'))
    ->withParsedBody([
        'grant_type' => JwtBearerGrant::IDENTIFIER,
        'assertion' => $assertion,
        'scope' => '',
    ]);
$response = DB::transaction(function () use ($assertion, $request, $verifier, $authorizationServer) {
    $verified = $verifier->verify($assertion);
    $user = User::query()->where('external_id', $verified->subject)->lockForUpdate()->first();
    if ($user === null || !$user->active) {
        throw new DomainException('No eligible local user.');
    }
    // Apply remaining application rate/eligibility rules here.
    $server = clone $authorizationServer;
    $server->enableGrantType(
        JwtBearerGrant::forVerifiedAssertion($verifier, $verified, (string) $user->getAuthIdentifier()),
        Passport::tokensExpireIn(),
    );
    $response = $server->respondToAccessTokenRequest($request, new Response());
    $verifier->assertValidAt($verified);
    return $response;
});
```

Use the actual verified snapshot from the same verifier and exact original JWT bytes. No second signature/key lookup or JWT rewriting occurs. Time is rechecked after waiting; native credentials, client grant restrictions and scope policy remain active. Supplied credentials are validated even with `OPTIONAL`. Local user ID is a trusted PHP argument; HTTP body/attributes cannot override it.

Choose the token/user connection explicitly for multi-connection applications. Wrap the complete response and final time check, handle errors outside the transaction and keep identity variables local. Scope `''` stays empty even with global defaults. No refresh token or application success audit is added. Refusal audit uses the application's trusted local variables and [structured reasons](rejections.md).

No Passport HTTP route is required. Preserve application route configuration; `Passport::ignoreRoutes()` can disable routes where appropriate. Native bearer guard and standard token revocation work normally.

## Already local subject: optional raw binding

Only when verified `sub` already is the local OAuth user ID:

```php
$this->app->singleton(JwtBearerGrant::class, fn ($app) => new JwtBearerGrant(
    $app->make(\Noldors\OAuth2JwtBearer\AssertionVerifier::class),
));
```

The provider enables this raw grant on the native server; raw requests always verify JWT fully. This binding is unsuitable for the CRM external-ID flow.
