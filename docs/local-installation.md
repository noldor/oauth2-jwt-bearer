# Local Composer installation and consumer handoff

The package is intentionally **not published**. The source checkout is:

```text
/home/noldor/work/packages/oauth2-jwt-bearer
```

The local development branch is `feature/jwt-bearer-grant`. A Composer path repository can use the corresponding development constraint without relaxing global stability:

```json
{
    "repositories": [
        {
            "type": "path",
            "url": "/home/noldor/work/packages/oauth2-jwt-bearer",
            "options": { "symlink": true }
        }
    ],
    "require": {
        "noldors/oauth2-jwt-bearer": "dev-feature/jwt-bearer-grant"
    }
}
```

Merge the repository entry and dependency into the consuming application's existing manifest; preserve its repositories and dependency constraints. Run its normal Composer update command scoped to `noldors/oauth2-jwt-bearer`, review the resulting application lock and rerun its own checks. If its PHP/Composer runs inside Docker, mount this host checkout into that runtime and use the **container-visible** path in `url`; the host path is not automatically visible inside a container. A read-only source mount works for package loading. A symlink installation reflects ongoing local package edits.

For reproducible installation without a development symlink, choose the path repository's `symlink: false` option and record the local package commit used. Neither mode publishes a package or reaches a package hosting service.

## Integration checklist for serton-mail

1. Read the application's own standards and accepted SM-9/CR-027 contract. This package does not authorize changing that contract, production settings or deployment.
2. Install from the local path and confirm compatibility against the application's actual PHP 8.5, Laravel 13, Passport 13.10 and League 9.4.1 graph. Package verification covers its own locked graph; the consumer's dependency graph still needs validation.
3. Configure trusted CRM issuer/audience, actual client ID, `Algorithm::ED25519`, `AssertionRequirements(60, 3, ['iat'])` and explicit authentication policy. `OPTIONAL` permits assertion-only input; supplied credentials remain validated.
4. Implement `KeyResolver` with trusted issuer/`kid` bindings and raw 32-byte public keys. Decode configured base64/hex first. Configure key rotation; legacy `EdDSA` is separate opt-in.
5. Bind only the verifier for CRM. Do not bind a raw grant to the shared server: CRM `sub` is an external ID.
6. In application `Token::issue`, verify, run existing user/claim/rate rules, lock/check the existing active User, then call `forVerifiedAssertion($verifier, $verified, $localUserId)` on a fresh local server clone. Use normal `Passport::tokensExpireIn()` set to one hour. No subject resolver, context adapter or replacement callback is needed; no second crypto runs.
7. Accept only assertion at GraphQL and construct server-owned OAuth parameters with explicit empty scope. Keep verification, locks, complete native response and final `assertValidAt($verified)` in one token/user SQL transaction; handle errors outside it. No HTTP routes, refresh token or success audit are required.
8. Remove CRM one-time storage/checks and required assertion `jti` from application contracts/implementation. Repeated valid assertions intentionally create new tokens. Native access-token `jti` remains unchanged.
9. Test consumer GraphQL errors, external-to-internal mapping, inactive/missing users, real lock waits/expiry, repeated exchange, issuance/signing rollback, refusal audit/rate policy, native guard/revocation, empty scopes under global defaults and no prepared identity retained by the shared server.

See [public API](../README.md), [Passport integration](passport.md), [design/profile](design.md) and [package verification](verification.md). Integration work belongs to the serton-mail project; this checkout changes no application files.
