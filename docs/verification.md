# Verification

Verification targets the package and its illustrative application wrappers only. No serton-mail files, dependencies, database or running service are modified here. There is no remote or package publication.

## Runtime and locked compatibility

The Docker/src/tests/docs layout follows the adjacent packages. The test runtime is PHP 8.5.12 on Linux x86-64, with an isolated PostgreSQL 16 service/volume and no published database ports. The synthetic test store uses trust authentication only on its package network. Native phanalist 1.2.1 is pinned with its published checksum during runtime setup; acceptance does not download an unpinned binary.

| Component | Locked/tested version |
| --- | --- |
| League OAuth2 Server | 9.4.1 |
| Laravel Passport | 13.10.0 |
| Laravel framework | 13.40.0 |
| lcobucci/jwt | 5.6.1 |
| Orchestra Testbench | 11.3.0 |
| PHPUnit | 13.4.6 |
| PHPStan | 2.3.5 |
| Shared PHPStan extension | 0.8.0 |
| Shared formatter preset | 1.4.1 |
| PHP-CS-Fixer | 3.95.29 |

Composer ranges describe downstream compatibility, not proof of every allowed combination. The committed lock SHA-256 is `c3acdef3cb9e815fa8c1f53348fbc78452be27a3081ee4f5dcd4c3ea3f086bd1`.

## Current boundary and coverage

`JwtBearerGrant($verifier)` fully verifies JWT and uses an already local subject. `forVerifiedAssertion($verifier, $verified, $localId)` accepts a trusted verified snapshot from application code, binds original bytes and avoids a second signature/key lookup. Only `KeyResolver` remains as an application contract. Native client/scopes/time/persistence/signing behavior is retained.

- Trusted issuer/key rotation, exact algorithm/key binding, raw claim types, signature/audience/issuer, bounded lifetime, leeway/nbf, extra constraints and injected clock.
- ES256/384/512, RS256/384/512, RFC 9864 Ed25519 default and distinct opt-in EdDSA, tampering, wrong allowlists/curves.
- Real League and Passport issuance, external-to-local mapping, credentials/grant restrictions, scopes/defaults/explicit empty scope, native guard/revocation and no required Passport routes.
- Prepared request binding, no second key resolution, ignored HTTP user IDs, isolated per-call identities and an unchanged shared server.
- Repeated valid assertion exchange and CRM without assertion `jti`, preserving native access-token `jti`.
- Structured reasons, safe generic native OAuth payload and application error boundaries.
- Expiry after application work, native persistence and the complete native response, with SQL rollback and signing-failure retry.
- An observed PostgreSQL lock wait between independent processes followed by fresh expiry rejection, trusted local identity retained and no persisted token.

There is no subject resolver, replacement user callback, assertion-use schema or one-time policy in source, examples or tests. Application operations own user/rate/ACTIVE rules, locks, one transaction around the complete response and a final public time check.

## Commands and evidence

```sh
docker compose -p oauth2-jwt-bearer run --rm app composer --no-plugins --no-scripts validate --strict
docker compose -p oauth2-jwt-bearer run --rm app composer check
docker compose -p oauth2-jwt-bearer run --rm app composer --no-plugins --no-scripts audit --locked --format=json
```

The test-first prepared-grant cases failed before the factory existed. A later review found that native parameter trimming weakened literal byte binding; the new leading/trailing-whitespace regression failed before the correction and now passes. The prepared path compares the original parsed-body string; raw native extraction remains unchanged.

The final `composer check` passed **137 tests / 559 assertions**, random seed `1794075650`, along with formatter, PHPStan max and pinned phanalist. Composer strict validation passed. A real Composer path consumer without Laravel or Passport passed raw and prepared native issuance, local-ID mapping, no second key lookup and structured error extraction.

Dependency lock and scanner/tool configuration are unchanged. Earlier same-day locked advisory checks and five native Betterleaks controls remain applicable. Current/index bytes and committed history are scanned before handoff; Composer/Git distribution archives are checked against the exact public allowlist. Tests, fixtures, development tooling and lock are excluded from distribution.

Remote CI has not run. The consumer's dependency graph, GraphQL, domain SQL/locking/rate rules, refusal audit and error mapping need their own acceptance checks. See [local installation](local-installation.md), [transaction example](transactions.md) and [structured rejections](rejections.md).

## Independent review and local handoff

Separate Requirements, Code quality, Security Guidance and Standards compliance reviews have no open findings. The Code quality review's exact-byte trimming defect was reproduced, fixed and rechecked by the affected reviewers. No new shared-rule or automated-check proposal is needed for this correction.

Current/index Betterleaks scanning is clean. Composer and staged Git archives match the exact public-file allowlist. Final prose changes receive the same byte scan/archive checks; committed history is scanned before handoff. The package remains unpublished. Consumers must remove the former resolver constructor argument/binding, use direct application user rules and choose raw or prepared issuance according to subject identity.
