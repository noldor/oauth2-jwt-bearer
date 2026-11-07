# OAuth2 JWT Bearer

Reusable [RFC 7523 §2.1](https://www.rfc-editor.org/rfc/rfc7523.html#section-2.1) authorization grant for League OAuth2 Server. PHP 8.5; Laravel-independent core; optional Passport integration. JWT client authentication (`client_assertion`) is deliberately outside this grant.

The package verifies an assertion and delegates access-token creation, persistence, signing, response formatting, scopes and revocation to League and the installed repositories. The application owns eligible users, issuer-to-client configuration, user locks, the transaction and local subject mapping. No application SQL schema, user model, audit implementation or HTTP endpoint is installed.

## Installation

After publishing the package to your Composer repository:

```sh
composer require noldors/oauth2-jwt-bearer
```

For local development, follow [local path installation](docs/local-installation.md). This checkout is a new package; publishing and connecting it to serton-mail are separate steps.

Runtime requirements include OpenSSL, sodium and mbstring. The committed development lock tests **PHP 8.5.12, Laravel 13, Passport 13.10.0 and League 9.4.1**. Passport is a development dependency and an optional integration, not a runtime dependency of the core. See [verification](docs/verification.md).

## Public API

```php
use Noldors\OAuth2JwtBearer\{
    AssertionRequirements,
    AssertionVerifier,
    ClientAuthentication,
    JwtBearerGrant,
    TrustedIssuer,
};

$issuer = new TrustedIssuer(
    issuer: 'https://crm.example',
    clientId: 'existing-oauth-client-id',
    audience: 'https://mail.example/assertion-exchange',
    requirements: new AssertionRequirements(
        maxLifetimeSeconds: 60,
        leewaySeconds: 3,
        requiredClaims: ['iat'],
    ),
    clientAuthentication: ClientAuthentication::OPTIONAL,
);

// $keys implements KeyResolver.
// $clock implements Psr\Clock\ClockInterface.
$verifier = new AssertionVerifier($keys, $clock, [$issuer]);
// Raw path: verified sub must already be the local OAuth user ID.
$grant = new JwtBearerGrant($verifier);

$authorizationServer->enableGrantType($grant, new DateInterval('PT1H'));
```

The default assertion algorithm is **`Ed25519`**, with exactly `alg: "Ed25519"` as registered by [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html#section-2.2). It does not change the signing algorithm of the access token issued by League/Passport.

The application implements only `KeyResolver::resolve(issuer, kid): ?VerificationKey`: return a trusted public key bound to one algorithm, or `null` for an untrusted/missing key. Keep multiple trusted key IDs during rotation; never trust keys or URLs supplied in JWT headers.

For an external subject, verify first and run application user/eligibility/locking rules directly. Then prepare a fresh grant on a per-call clone of the native server:

```php
$verified = $verifier->verify($assertion);
// Application finds/locks an eligible existing user using $verified->subject.
$server = clone $authorizationServer;
$server->enableGrantType(
    JwtBearerGrant::forVerifiedAssertion($verifier, $verified, (string) $user->id),
    new DateInterval('PT1H'),
);
$response = $server->respondToAccessTokenRequest($request, $responsePrototype);
$verifier->assertValidAt($verified); // Fresh time after the full response, before commit.
```

This trusted in-process API requires the actual `VerifiedAssertion` returned by the same configured verifier and a trusted local user ID. It binds the request to the exact original JWT bytes and retains the verified issuer/subject/profile snapshot. It **does not verify the signature or resolve keys a second time**. Fresh time and native client/scopes checks still run. HTTP body/attribute `user_id` never selects identity. Do not retain a prepared grant on a shared server or singleton. The raw constructor always performs full verification and uses verified `sub` as the local identifier.

There is no subject resolver, user callback, assertion-use repository or storage hook. Assertions can be exchanged repeatedly while valid. CRM uses `requiredClaims: ['iat']`, without required assertion `jti`. Generic defaults additionally require `jti` as a claim without recording its use. Native access-token `jti` is unchanged. Wrap verification, application locks/rules, complete response generation and the final public time check in one application transaction.

See [League setup](docs/league.md), [Passport setup](docs/passport.md), and the [transaction contract](docs/transactions.md).

## Algorithms and keys

Each issuer has an explicit allowlist. Its default contains only `Algorithm::ED25519`. To choose other algorithms, pass `allowedAlgorithms: [Algorithm::ES256]`, for example. The grant checks both the issuer allowlist and the algorithm bound to the resolved key before verifying the signature.

| Enum case | JWT `alg` | Trusted public-key format |
| --- | --- | --- |
| `ED25519` | `Ed25519` | Raw 32-byte Ed25519 public key |
| `EDDSA` | `EdDSA` | Raw 32-byte Ed25519 public key; explicit legacy compatibility |
| `ES256` | `ES256` | PEM, P-256 (`prime256v1`) |
| `ES384` | `ES384` | PEM, P-384 (`secp384r1`) |
| `ES512` | `ES512` | PEM, P-521 (`secp521r1`) |
| `RS256` | `RS256` | PEM RSA, at least 2048 bits |
| `RS384` | `RS384` | PEM RSA, at least 2048 bits |
| `RS512` | `RS512` | PEM RSA, at least 2048 bits |

```php
use Lcobucci\JWT\Signer\Key\InMemory;
use Noldors\OAuth2JwtBearer\{Algorithm, VerificationKey};

// Decode your trusted configuration's encoding before constructing the key.
$verificationKey = new VerificationKey(
    Algorithm::ED25519,
    InMemory::plainText($rawEd25519PublicKey),
);
```

`lcobucci/jwt 5.6.1` labels its Ed25519 signer `EdDSA`. The package's small `Signer` adapter supplies the RFC 9864 `Ed25519` identifier and delegates all cryptography to that library. `EdDSA` and `Ed25519` are separate, case-sensitive identifiers: neither automatically enables the other. Legacy `EDDSA` supports Ed25519 only, matching the installed sodium-backed signer; Ed448 is unsupported. Each `kid` resolves to one algorithm. A migration needing both identifiers must configure distinct key IDs/bindings explicitly. See [design notes](docs/design.md).

## Validation and client authentication

`iss`, `sub`, `aud` and `exp` are always required. Issuer and audience use exact comparison against trusted configuration; `aud` may be a string or a nonempty list of strings. `kid` is required. Unknown critical headers are rejected. Numeric dates must be JSON numbers. `nbf` and `iat`, when present, are checked with the injected PSR clock. Defaults additionally require `iat` and `jti`, and limit `0 < exp - iat <= 60` seconds. Assertion lifetime, leeway and the server's access-token TTL are independent.

If `iat` is intentionally optional, the maximum lifetime limits `exp` relative to the current verification time; it cannot establish token age without `iat`. Additional `requiredClaims` impose presence, while Lcobucci `Constraint` instances in `AssertionRequirements::constraints` enforce values or application-specific claim semantics after signature verification.

`ClientAuthentication::REQUIRED` is the default and requires valid client credentials for the mapped client. `OPTIONAL` permits credentials to be omitted because a trusted issuer already maps to a specific OAuth client. If any client identification/credentials are supplied, both modes require authentication: form `client_id`/`client_secret` or HTTP Basic. A client ID alone is not an unauthenticated selector. Supplied credentials never override the issuer's configured client. Mixed authentication methods, malformed Authorization headers and unsupported `client_assertion` are rejected. Repositories remain responsible for client activity and allowed grants.

Malformed/missing request parameters use League `invalid_request`; rejected assertions use `invalid_grant`; invalid credentials use `invalid_client`; disallowed grants use `unauthorized_client`; unknown scopes use `invalid_scope`. League builds the standard OAuth response/error representation. The grant never issues refresh tokens. Assertion failures retain `AssertionRejected` with a readonly `AssertionRejectionReason` through the OAuth exception’s `getPrevious()` chain. See [structured rejection and application audit](docs/rejections.md) for reason mapping, trusted local User/client variables and application-exception passthrough.

## Development

Use the same package layout and Docker workflow as the adjacent `lighthouse-extensions` and `lighthouse-idempotency` packages:

```sh
docker compose -p oauth2-jwt-bearer build app
docker compose -p oauth2-jwt-bearer run --rm app composer --no-plugins --no-scripts install --no-interaction
docker compose -p oauth2-jwt-bearer run --rm app composer check
docker compose -p oauth2-jwt-bearer down --volumes --remove-orphans
```

`composer check` runs the shared formatter preset, PHPStan max with Larastan/shared rules, phanalist and all PHPUnit tests in random order. PostgreSQL and worker processes belong only to this package. Concurrent suites share their store and must run sequentially; they coordinate actual PostgreSQL lock waits and check durable state. Mutation tooling is installed but is run only on explicit request. Advisory and secret checks are separate verification gates.
