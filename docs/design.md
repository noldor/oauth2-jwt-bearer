# Design and prior art

## Scope and extension points

The implementation was preceded by inspection of [pmg/assertion-grant v0.6.0](https://github.com/AgencyPMG/league-oauth2-server-assertion-grant/tree/v0.6.0), including `AssertionGrant`, `JwtAssertionGrantBackend`, its assertion/key repositories and `HasValidExpiration` constraint. It demonstrates the correct supported League extension: `AbstractGrant`, `enableGrantType()`, `issueAccessToken()`, repositories, scope finalization and the normal bearer response. This package follows those mechanisms without depending on or copying the PMG implementation.

The confirmed requirements need different boundaries:

- Issuer is not assumed to be the OAuth client ID; subject is not assumed to be a local user ID.
- Assertion maximum lifetime is independent of access-token TTL.
- Issuer-scoped `kid` resolution, explicit per-key algorithm binding and a per-issuer allowlist establish trust outside the JWT.
- Replay belongs entirely to the complete application issuance operation, after the native response returns. The grant has no storage dependency or callback. An application may atomically link `(issuer, jti)` to the issued token and recheck time through the public verifier before committing.
- The application transaction covers token persistence, replay recording, user row locks and response signing. No persistence implementation or cleanup schema is part of the core.
- The grant checks time after subject resolution/scope finalization and after native token persistence. If its own replay insert waits after the response, the application calls public `AssertionVerifier::assertValidAt()` again before commit.

The public surface has one grant, verifier/configuration values, two application contracts and the standard Lcobucci constraint interface for extra claim requirements. A separate exchange framework, Laravel user abstraction, JWT client-authentication mechanism, key-discovery service and application audit layer are unnecessary for the confirmed consumer.

## Algorithm identifiers

[RFC 9864 §2.2](https://www.rfc-editor.org/rfc/rfc9864.html#section-2.2) registers fully specified `Ed25519` and `Ed448` and deprecates polymorphic `EdDSA`. The [IANA JOSE registry](https://www.iana.org/assignments/jose/jose.xhtml) lists the separate identifiers. JOSE `ES256`/`ES384`/`ES512` already identify their exact curves; the corresponding COSE renaming does not change these JWT identifiers.

Installed `lcobucci/jwt 5.6.1` implements `Signer\Eddsa` using sodium's Ed25519 operations and returns `EdDSA` from `algorithmId()`. Its `SignedWith` constraint compares that string exactly with the JWT header. Consequently, using its native signer directly with `alg: Ed25519` fails before cryptographic verification.

The package implements the library's supported `Signer` interface to adapt just this identifier. Signing and verification delegate to the native `Eddsa` signer. The token header/payload are never rewritten. Interoperability tests produce signed bytes independently, prove native `SignedWith(Eddsa)` rejects the new identifier, prove the adapter accepts the original `Ed25519` bytes, and exercise explicit legacy `EdDSA` separately. Default configuration permits only `Ed25519`.

Key format validation requires raw Ed25519 public keys of exactly 32 bytes, exact NIST curves for ECDSA, and RSA public keys of at least 2048 bits. Binary length is measured as bytes even when mbstring uses a multibyte default encoding.

## First consumer: serton-mail

The agreed profile now uses **Ed25519 with `alg: Ed25519`**, superseding the initial RS256 profile. A separate one-time CRM confirmation supplies trusted `iss`, `aud`, `kid`, external `sub` and mandatory `iat`, `exp`, `jti`. Lifetime is `0 < exp - iat <= 60` seconds; leeway is 3 seconds; `nbf` is supported. The application finds and locks an existing active user and supplies its internal ID. The application issuance operation uses the same SQL transaction for the native response, its own replay insert and the public post-insert clock check. The package stores no assertion use. The access token lasts one hour, with an empty scope request and no refresh token.

GraphQL accepts only the assertion. A server-owned adapter constructs OAuth parameters and calls the standard AuthorizationServer without publishing Passport routes. Activity checks, rate limits, user locks and refusal audit remain in the consuming application. Successful issuance is not sent to application audit. Native League/Passport lifecycle events retain their normal framework semantics.

Integrating this package into serton-mail, changing that application's dependencies, CRM signing setup, schema, GraphQL, audit or deployment remains a subsequent task.
