# League integration

Use the normal `AuthorizationServer`, client/scope/access-token repositories, signing key and encryption key. The package extends `AbstractGrant`; League creates/persists tokens and signs the complete response. The TTL passed to `enableGrantType()` is independent of assertion lifetime/leeway.

## Trusted keys and claims

Implement the only application contract with preloaded issuer-scoped keys:

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

Construct `VerificationKey(Algorithm::ED25519, InMemory::plainText($rawPublicKey))` with a raw 32-byte key. Keep old/new `kid` bindings during rotation. JWT-provided URLs, certificates and keys establish no trust. Trusted infrastructure failures propagate; an untrusted/missing key returns `null`. See [configuration and algorithm formats](../README.md).

Additional claims use standard Lcobucci constraints:

```php
$requirements = new \Noldors\OAuth2JwtBearer\AssertionRequirements(
    maxLifetimeSeconds: 60,
    leewaySeconds: 3,
    requiredClaims: ['iat', 'purpose'],
    constraints: [new \Lcobucci\JWT\Validation\Constraint\HasClaimWithValue('purpose', 'mail-login')],
);
```

Mandatory RFC claims and numeric date types are always checked. PSR Clock controls assertion validation; access-token timestamps retain native League behavior.

## Raw grant for an already local subject

```php
$authorizationServer->enableGrantType(
    new \Noldors\OAuth2JwtBearer\JwtBearerGrant($verifier),
    new DateInterval('PT1H'),
);
```

The raw path fully verifies the original JWT and uses verified `sub` as the local OAuth user ID. Use it only where that mapping is correct. Client identity comes from trusted issuer configuration. `OPTIONAL` allows omitted credentials; any supplied credentials are validated. `REQUIRED` requires valid mapped-client credentials. Normal scope policy applies.

## External subject and programmatic exchange

The application verifies, finds/locks its User and applies eligibility/rate rules directly. Then call `JwtBearerGrant::forVerifiedAssertion($verifier, $verified, $localUserId)` and register the fresh grant on a **per-call clone** of the native server. Pass the actual verified object from the same verifier. This privileged API performs no second signature/key lookup, retains the verified issuer/subject/profile and binds the original JWT bytes. Native client/scopes and fresh time checks still run. Empty local ID throws `InvalidArgumentException`.

No resolver, callback, custom server, request attribute or JWT rewriting is needed. HTTP body/attribute `user_id` is ignored. Do not retain prepared grants on shared servers.

An assertion-only adapter constructs a server-owned PSR request:

```php
$request = (new \Nyholm\Psr7\ServerRequest('POST', 'https://mail.example/internal/exchange'))
    ->withParsedBody([
        'grant_type' => \Noldors\OAuth2JwtBearer\JwtBearerGrant::IDENTIFIER,
        'assertion' => $assertion,
        'scope' => '',
    ]);
```

The URI is metadata, not a required route; audience is trusted configuration and may differ. Nyholm is an example PSR implementation, not a core dependency. Do not forward inbound GraphQL Authorization or caller-selected OAuth clients/scopes. For `REQUIRED`, add server-owned credentials.

Follow the [complete transaction example](transactions.md). Signing occurs during `respondToAccessTokenRequest()`. Handle errors outside the transaction; an error returned as a successful callback result could commit partial writes. Standard OAuth errors can use `generateHttpResponse()`; GraphQL can map errors at its own boundary.
