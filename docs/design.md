# Design and prior art

## Scope and extension points

The implementation was preceded by inspection of [pmg/assertion-grant v0.6.0](https://github.com/AgencyPMG/league-oauth2-server-assertion-grant/tree/v0.6.0), including `AssertionGrant`, `JwtAssertionGrantBackend`, its assertion/key repositories and `HasValidExpiration` constraint. It demonstrates the correct supported League extension: `AbstractGrant`, `enableGrantType()`, `issueAccessToken()`, repositories, scope finalization and the normal bearer response. This package follows those mechanisms without depending on or copying the PMG implementation.

The confirmed requirements need different boundaries:

- Issuer is not assumed to be the OAuth client ID; subject is not assumed to be a local user ID.
- Assertion maximum lifetime is independent of access-token TTL.
- Issuer-scoped `kid` resolution, explicit per-key algorithm binding and a per-issuer allowlist establish trust outside the JWT.
- The raw grant fully verifies JWT and uses a subject that already represents a local OAuth ID.
- For external IDs, application code verifies first, finds/locks its User, applies domain rules and passes the local ID to `forVerifiedAssertion()` on a per-call server clone.
- The prepared API trusts the actual verified object, binds original bytes, retains issuer/subject/profile and performs no second crypto/key lookup. Fresh time and native client/scopes checks remain active.
- One transaction covers user locks, token persistence, complete signing/response and a final public time check. There is no assertion-use storage or one-time policy.

The public surface has one grant, verifier/configuration values, one trusted key resolver contract and standard Lcobucci claim constraints. No subject resolver, user callback, custom AuthorizationServer or application audit framework is supplied.

## Algorithm identifiers

[RFC 9864 §2.2](https://www.rfc-editor.org/rfc/rfc9864.html#section-2.2) registers fully specified `Ed25519` and `Ed448` and deprecates polymorphic `EdDSA`. The [IANA JOSE registry](https://www.iana.org/assignments/jose/jose.xhtml) lists the separate identifiers. JOSE `ES256`/`ES384`/`ES512` already identify their exact curves; the corresponding COSE renaming does not change these JWT identifiers.

Installed `lcobucci/jwt 5.6.1` implements `Signer\Eddsa` using sodium's Ed25519 operations and returns `EdDSA` from `algorithmId()`. Its `SignedWith` constraint compares that string exactly with the JWT header. Consequently, using its native signer directly with `alg: Ed25519` fails before cryptographic verification.

The package implements the library's supported `Signer` interface to adapt just this identifier. Signing and verification delegate to the native `Eddsa` signer. The token header/payload are never rewritten. Interoperability tests produce signed bytes independently, prove native `SignedWith(Eddsa)` rejects the new identifier, prove the adapter accepts the original `Ed25519` bytes, and exercise explicit legacy `EdDSA` separately. Default configuration permits only `Ed25519`.

Key format validation requires raw Ed25519 public keys of exactly 32 bytes, exact NIST curves for ECDSA, and RSA public keys of at least 2048 bits. Binary length is measured as bytes even when mbstring uses a multibyte default encoding.

## First consumer: serton-mail

The agreed profile uses **Ed25519 with `alg: Ed25519`**, superseding the initial RS256 profile. CRM supplies trusted issuer/audience/key ID, external `sub` and mandatory `iat`, `exp`. There is no required assertion `jti` or one-time semantics. Use `AssertionRequirements(60, 3, ['iat'])`: `0 < exp - iat <= 60`, leeway 3 seconds, optional `nbf`. Application code verifies, finds/locks an existing active User and passes its internal ID through the prepared API. The complete response and final time check share that SQL transaction. Access tokens last one hour, with empty scopes, no refresh token and normal native token `jti`.

GraphQL accepts only the assertion. A server-owned adapter constructs OAuth parameters and calls the standard AuthorizationServer without publishing Passport routes. Activity checks, rate limits, user locks and refusal audit remain in the consuming application. Successful issuance is not sent to application audit. Native League/Passport lifecycle events retain their normal framework semantics.

Integrating this package into serton-mail, changing that application's dependencies, CRM signing setup, schema, GraphQL, audit or deployment remains a subsequent task.
