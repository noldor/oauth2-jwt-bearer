# Laravel Passport integration

The optional provider uses Laravel's `afterResolving(AuthorizationServer::class)` callback and League's `enableGrantType()`. It uses Passport's existing client/token/scope repositories and configured `Passport::tokensExpireIn()`. It does not copy a Passport provider, subclass its internals, patch vendor, publish migrations or register routes.

## Application registration

Laravel auto-discovers `Noldors\OAuth2JwtBearer\Passport\JwtBearerServiceProvider`. If discovery is disabled, register it in `bootstrap/providers.php`. It activates the grant only if the application explicitly binds `JwtBearerGrant::class`; auto-wiring an otherwise unconfigured grant is not attempted.

In your application provider's `register()` method, bind a fresh configured grant:

```php
use Noldors\OAuth2JwtBearer\{AssertionVerifier, JwtBearerGrant};
use Noldors\OAuth2JwtBearer\Contracts\{KeyResolver, SubjectResolver};
use Psr\Clock\ClockInterface;

$this->app->singleton(AssertionVerifier::class, function ($app): AssertionVerifier {
    return new AssertionVerifier(
        $app->make(KeyResolver::class),
        $app->make(ClockInterface::class),
        $app->make(TrustedCrmIssuer::class)->profiles(),
    );
});
$this->app->bind(JwtBearerGrant::class, function ($app): JwtBearerGrant {
    return new JwtBearerGrant(
        $app->make(AssertionVerifier::class),
        $app->make(SubjectResolver::class),
    );
});
```

`TrustedCrmIssuer` here is your application's configuration owner, returning the `TrustedIssuer` profile shown in the README; it is not a package class. Bind both application contracts and the PSR clock before resolving AuthorizationServer. Inject the same configured `AssertionVerifier` into the application issuance operation for its post-insert time check. Supply per-invocation subject/audit context through application composition rather than retaining request state in a shared grant or resolver.

Create/use a normal Passport client and explicitly include `JwtBearerGrant::IDENTIFIER` in that client's `grant_types`, alongside any grants it already needs. Configure the profile's `clientId` to the actual stored client ID; do not derive it from `iss`. Revoked clients and clients lacking this grant are rejected through Passport/League. Standard Passport client-secret hashing and validation apply when credentials are supplied.

If you want the standard Passport token lifetime to be an hour, set `Passport::tokensExpireIn(new DateInterval('PT1H'))` in your application provider before the AuthorizationServer is first resolved. Changing this default also affects other Passport grants, following normal Passport behavior. For a grant-specific lifetime, opt out of this package's auto-discovery and register your configured grant yourself in an `afterResolving` callback with an explicit League TTL. No custom access-token entity or bearer guard is required.

## Assertion-only application operation

The application issuance operation owns OAuth client parameters, empty scope, the transaction and replay SQL. No replay service or repository contract is supplied by the package. The application's subject resolver can find an existing active user by external ID using `lockForUpdate()`, retain the `VerifiedAssertion` in the invocation context, then return the internal user ID. The grant rechecks the assertion time after this resolver returns, including after waiting on the lock.

```php
use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\AuthorizationServer;
use Noldors\OAuth2JwtBearer\JwtBearerGrant;
use Nyholm\Psr7\{Response, ServerRequest};

$request = (new ServerRequest('POST', 'https://mail.example/internal/exchange'))
    ->withParsedBody([
        'grant_type' => JwtBearerGrant::IDENTIFIER,
        'assertion' => $assertion,
        'scope' => '',
    ]);

$response = DB::transaction(function () use ($authorizationServer, $request, $verifier, $context) {
    $response = $authorizationServer->respondToAccessTokenRequest($request, new Response());
    // Continue in the application use case: extract the issued token ID from
    // its trusted native response, atomically insert jti -> token ID, handle
    // duplicate-key replay, then recheck after possible SQL contention.
    $verifier->assertValidAt($context->assertion);
    return $response;
});
```

The example marks the application-owned insert step; the [complete transaction example](transactions.md) shows the atomic SQL and token-ID extraction. Keep that work directly in the complete issuance use case, such as `Token::issue`.

Inject the normal `AuthorizationServer` and the appropriate database connection into the complete application use case. This example uses the facade only to make the transaction boundary visible. The application’s replay insert and Passport token model must share that connection; account for `passport.connection` and any custom Passport models. Do not wrap Passport's HTTP controller instead: an error converted to a response inside your transaction could commit a losing token. The direct AuthorizationServer call throws until handled outside the transaction.

To keep Passport's HTTP routes closed, call `Passport::ignoreRoutes()` from an application provider's `register()` method, before Passport boots. The PSR request above needs no matching HTTP route. GraphQL can expose only `assertion` and translate the returned standard OAuth body into its application result.

## First-consumer profile and lifecycle

The current serton-mail profile is **Ed25519 / `alg: Ed25519`**, mandatory `iat`, `exp`, `jti`, lifetime at most 60 seconds, leeway 3 seconds and optional `nbf`. Audience, issuer and key IDs are configured in advance. The package defaults match the algorithm/lifetime/required claims; configure the 3-second leeway and mapped client explicitly. `ClientAuthentication::OPTIONAL` permits the trusted server adapter to omit client credentials. Any credentials supplied are still authenticated.

The exchanged token is a standard Passport token. `auth:api` / the Passport bearer guard loads the mapped local user; Passport's normal token repository revokes the token. Scope lookup/finalization goes through Passport. Set `scope` to `''` for the first consumer even if other application flows configure default scopes. The grant produces no refresh token.

Business activity checks, rate limits, row locks and refusal audit belong to the application. No success audit is added. The Passport integration tests (`tests/Integration/PassportGrantTest.php` in the source checkout) exercise the real Laravel/Passport container and migrations, programmatic issuance with no Passport routes, client restrictions/credentials, scope persistence, bearer authentication, standard revocation and transaction rollback.

For the existing refusal-audit taxonomy, use [structured rejection reasons](rejections.md) from the native OAuth exception's previous chain. Retain the trusted User/client in application-owned per-exchange context; post-wait expiry does not clear it. Consumer exceptions for rate policy, missing/deleted users and replay propagate without conversion.
