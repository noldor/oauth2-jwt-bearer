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

## Current boundary

The native grant has only verifier and subject-resolver dependencies. It verifies JWT/client/scopes and delegates normal access-token issuance/signing/persistence to League/Passport. It performs fresh time checks after subject/scope work and after native token persistence. There is no assertion-use repository, storage callback or automatic replay tracking in the package.

Test application operations own one transaction around the complete native response, their later atomic replay insert and a public verifier time check after possible insert contention. Those examples prove a consuming application's composition; they do not turn replay into a grant capability. Direct native-grant tests separately prove that no replay record is written and the same assertion can be exchanged again while valid. Default `jti` requirements remain claim policy; a profile can deliberately omit that requirement.

## Behavioral coverage

- Trusted issuer/key rotation, exact algorithm/key binding, raw claim types, signature/audience/issuer validation, bounded lifetime, leeway/nbf, extra constraints and PSR-clock boundaries.
- ES256/384/512, RS256/384/512, exact RFC 9864 Ed25519 default and separate opt-in legacy EdDSA, including tampering and wrong allowlists/curves.
- Real League and Passport native issuance, mapped users, client credentials/grants, scope defaults/explicit empty scope, Passport bearer guard/revocation and programmatic operation without Passport routes.
- Structured rejection reasons, the exact preserved previous exception, generic safe OAuth payload, no input-bearing vendor cause, and unchanged application-exception passthrough.
- Fresh grant time checks after user resolution and native persistence; application-owned post-response expiry/replay rejection and rollback before retry.
- Actual observed PostgreSQL waits between separate processes: one successful application replay-protected exchange, expiry while waiting for a user row lock, and direct structured rejection from the application's public time check after replay-insert contention. Trusted invocation-local identity remains available after rollback.
- Application-example FK controls reject orphan links and restricted token deletion/update. The package supplies no schema or migrations.

## Commands and evidence

```sh
docker compose -p oauth2-jwt-bearer run --rm app composer --no-plugins --no-scripts validate --strict
docker compose -p oauth2-jwt-bearer run --rm app composer check
docker compose -p oauth2-jwt-bearer run --rm app composer --no-plugins --no-scripts audit --locked --format=json
```

The replay-removal red phase demonstrated both old boundary violations: the native grant wrote an assertion-use row, and a profile without required `jti` was still rejected by storage coupling. Both cases pass after the removal. The final full gate, including the post-review UTC-serialization correction, passed **145 tests / 676 assertions** with random seed `1794072359`, the shared formatter, PHPStan max and pinned phanalist.

Earlier same-day locked advisory checks were clean. Dependencies, lock, scanner/tool configuration are unchanged, so those results and five native Betterleaks controls remain applicable. The controls cover allowed/prohibited/changed synthetic tokens, errors, lockfile scanning, broken symlinks, intermediate additions later removed, file-type transitions and merge-only additions. Current/index bytes and committed history are scanned before handoff. Composer and Git distribution archives are verified against the exact public allowlist; tests/fixtures/tooling and the development lock stay out of distribution.

Remote CI/hosting protection has not run. The consumer's actual dependency graph, application SQL/replay policy, identity/audit context and error mapping remain separate acceptance boundaries. See [local installation](local-installation.md), [application transaction example](transactions.md) and [structured rejections](rejections.md).


## Independent review and handoff

Requirements, Code quality and Security reviews found no issues in this removal. Standards compliance identified one inherited serializer issue in the moved application examples: SQL-style timestamp strings lacked explicit UTC normalization. The two fixture writers and SQL example now use UTC ISO 8601 with six fractional digits; that P3 is fixed and source-reverified. There are no open review findings, and no new shared standards or automated-check proposals.

A real Composer path consumer without Laravel/Passport passed repeated direct native issuance without consuming an assertion, plus structured error extraction. Current documentation links and absence of the removed API were checked. The package remains unpublished; the consumer must remove the old third constructor argument/bindings and own its SQL/time check directly in the complete issuance operation.
