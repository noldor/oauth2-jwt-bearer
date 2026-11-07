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
3. Configure `TrustedIssuer` with the CRM issuer/audience, actual Passport client ID, `Algorithm::ED25519`, `AssertionRequirements(60, 3, ['iat', 'jti'])` and the explicitly selected client-authentication policy. `ClientAuthentication::OPTIONAL` allows the assertion-only internal adapter to omit client credentials; any supplied credentials are still validated. Use `REQUIRED` when the server adapter is to authenticate with the mapped client's secret.
4. Implement `KeyResolver` for trusted issuer/`kid` bindings. `VerificationKey(Algorithm::ED25519, InMemory::plainText($rawPublicKey))` requires a raw 32-byte public key. Decode trusted configuration's base64/hex first. Configure multiple key IDs for rotation. Legacy `EdDSA` is a separate opt-in algorithm and is not the default.
5. Implement `SubjectResolver` to find an existing active user by the verified external subject, lock it in the issuance transaction and return the internal ID. Eligibility, rate limiting and refusal audit remain application-owned.
6. Implement `AssertionUsageRepository::record()` using one atomic unique insert for `(issuer, jti)` linked to the actual issued token. Use the same connection as Passport and the user lock. Retain usage through `exp + 3 seconds`; throw `AssertionRejected` on replay. See [transaction contract](transactions.md).
7. Bind the configured grant before resolving AuthorizationServer. The optional provider registers it with Passport's normal access-token lifetime; set the agreed hour before server resolution, or register it directly with an explicit grant-specific League TTL.
8. The application use case accepts only assertion at GraphQL, constructs the server-owned PSR request with the JWT-bearer grant and explicit empty scope, and wraps the entire AuthorizationServer response in the SQL transaction. Handle exceptions outside that transaction. No success audit or refresh token is added. Passport routes need not be exposed.
9. Add consumer tests for GraphQL inputs/errors, inactive/missing users, real lock waits/expiry, concurrent replay, issuance/signing rollback, refusal audit/rate policies and standard Passport guard/revocation. Confirm the empty scope remains empty even with global Passport defaults configured.

See [public API](../README.md), [Passport integration](passport.md), [design/profile](design.md) and [package verification](verification.md). Integration work belongs to the serton-mail project; this checkout changes no application files.
