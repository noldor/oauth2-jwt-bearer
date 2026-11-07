# League integration

Construct your normal League `AuthorizationServer` with its client, scope and access-token repositories, signing key and encryption key. Register `JwtBearerGrant` using `enableGrantType($grant, new DateInterval('PT1H'))`. The library's repositories create and persist the access token; the library signs it when the complete HTTP response is generated. The package adds no token repository of its own.

## Trusted keys

Implement an issuer-scoped key resolver using configuration, your key repository or a trusted key-distribution system. This minimal resolver illustrates rotation with preloaded keys:

```php
use Noldors\OAuth2JwtBearer\Contracts\KeyResolver;
use Noldors\OAuth2JwtBearer\VerificationKey;

final readonly class ConfiguredKeys implements KeyResolver
{
    /** @param array<string, array<string, VerificationKey>> $keys */
    public function __construct(private array $keys) {}

    public function resolve(string $issuer, string $keyId): ?VerificationKey
    {
        return $this->keys[$issuer][$keyId] ?? null;
    }
}
```

Construct `VerificationKey(Algorithm::ED25519, InMemory::plainText($rawPublicKey))` for each trusted Ed25519 key. Keep the old key under its old `kid` while still-valid assertions may arrive. Removing the old binding stops accepting it. A header-supplied URL, certificate or key is never a source of trust. If keys are fetched by your resolver, issuer-to-endpoint configuration and fetch/cache/rotation policy belong to that trusted resolver.

## Subject and claims

Implement `SubjectResolver` to map `$assertion->subject` under `$assertion->issuer->issuer`, enforce current eligibility, acquire application locks and return the internal user identifier. Throw `AssertionRejected` for an expected ineligible/unknown subject; allow database/unexpected failures to propagate. The resolver receives already-verified claims through `$assertion->token->claims()`.

For extra claims, use the installed library's standard constraint extension:

```php
use Lcobucci\JWT\Validation\Constraint\HasClaimWithValue;
use Noldors\OAuth2JwtBearer\AssertionRequirements;

$requirements = new AssertionRequirements(
    maxLifetimeSeconds: 60,
    leewaySeconds: 3,
    requiredClaims: ['iat', 'jti', 'purpose'],
    constraints: [new HasClaimWithValue('purpose', 'mail-login')],
);
```

The package always checks the mandatory RFC claims and NumericDate types regardless of the extra requirements. PSR Clock controls assertion validation. Access-token timestamps retain League's native behavior.

## Programmatic exchange

Your adapter can accept just the assertion and create a server-owned request. Do not copy an inbound GraphQL Authorization header or allow caller-supplied OAuth client/scope overrides into this request.

```php
use Nyholm\Psr7\{Response, ServerRequest};
use Noldors\OAuth2JwtBearer\JwtBearerGrant;

$request = (new ServerRequest('POST', 'https://mail.example/internal/exchange'))
    ->withParsedBody([
        'grant_type' => JwtBearerGrant::IDENTIFIER,
        'assertion' => $assertion,
        'scope' => '',
    ]);

$connection->beginTransaction();
try {
    $response = $authorizationServer->respondToAccessTokenRequest($request, new Response());
    // The application may now perform its own atomic replay insert and call
    // $verifier->assertValidAt($context->assertion) before committing.
    $connection->commit();
} catch (Throwable $exception) {
    $connection->rollBack();
    throw $exception;
}
```

This URI is metadata for the in-memory PSR request, not a route that must exist. A trusted configured audience may be different from that URI. Nyholm PSR-7 is an example implementation, not a runtime requirement of the core; use your existing PSR-7 implementation.

With `ClientAuthentication::REQUIRED`, supply the mapped client's correct `client_id` and `client_secret` in the server-owned body, or authenticate using HTTP Basic. With `OPTIONAL`, omit both. Credentials received by any direct OAuth request are still verified.

Handle `OAuthServerException` outside the transaction and call `generateHttpResponse()` if exposing the standard OAuth error representation. GraphQL may instead translate that error at its normal application boundary. Never catch it inside a transaction and turn rejection into a successful transaction commit. See [the complete application transaction example](transactions.md) for replay SQL after the native response and the actual League integration tests (`tests/Integration/LeagueGrantTest.php` in the source checkout).
