# Verification

Local verification targets the new package only. No serton-mail repository files, dependencies, database or running service are modified. No package publication is performed.

## Runtime and locked compatibility

The package follows the adjacent packages' Docker/Composer/src/tests/docs layout. The development container is PHP 8.5.12 on Linux x86-64, with a package-specific PostgreSQL 16 service/volume with no published ports. This synthetic test store uses passwordless trust authentication inside its package network. The pinned native phanalist 1.2.1 release is installed with its published SHA-256 during Docker build; acceptance never invokes the Composer wrapper that fetches `latest`.

The committed graph resolves:

| Component | Tested version |
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

Composer ranges describe downstream compatibility. The tests prove the locked combination above, not every version allowed by those ranges.

## Behavioral coverage

- The verifier matrix covers trusted issuers/rotated key IDs, signature/algorithm rejection, exact audience and claim types, positive bounded lifetime, leeway boundaries, `nbf`, required/optional claims, additional Lcobucci constraints and fresh clock checks.
- Every supported RSA/ECDSA/Ed25519/legacy-EdDSA identifier has valid, tampered-signature and disallowed-algorithm cases. Tests enforce exact EC curves and per-key algorithm binding. Native `SignedWith(Eddsa)` incompatibility with `alg: Ed25519` and the RFC 9864 adapter are tested explicitly.
- A real League AuthorizationServer issues and signs the token, uses repositories/scopes and returns normal OAuth errors. Tests cover required/optional client authentication, form/Basic credentials, client mismatch, replay and durable rollback before retry after persistence or signing failures.
- Real Laravel/Passport integration uses Passport migrations, existing client/token/scope repositories and the service-provider callback. It tests programmatic issuance without Passport routes, external-to-internal user mapping, inactive users, explicit client grants, client secrets, scopes, the bearer guard and standard revocation. Signing/application failures roll back token/use records.
- Concurrent tests use independent PHP processes and PostgreSQL connections. The coordinator observes an actual database lock wait before releasing the competing writer. Replay produces exactly one successful issuance and one committed linked token/use pair. Expiration while waiting for a real user row lock is rejected with no token/use persisted.

## Commands and handoff

```sh
docker compose -p oauth2-jwt-bearer run --rm app composer --no-plugins --no-scripts validate --strict
docker compose -p oauth2-jwt-bearer run --rm app composer check
docker compose -p oauth2-jwt-bearer run --rm app composer --no-plugins --no-scripts audit --locked --format=json
```

## Completed local results — 2026-11-07

- Composer 2.10.3 manifest/lock validation: passed with no schema warnings. Lock SHA-256: `c3acdef3cb9e815fa8c1f53348fbc78452be27a3081ee4f5dcd4c3ea3f086bd1`.
- `composer check`: shared formatter, PHPStan max and pinned native phanalist passed; PHPUnit passed **108 tests / 315 assertions** in random order (seed `1794066779`).
- A separate `composer install --no-dev` graph executed a real League exchange with an application-supplied Nyholm PSR-7 implementation while Laravel and Passport were absent. This verifies the core's dependency boundary in addition to the dev-graph integration tests.
- Locked Composer audit covered runtime/development packages and completed with no reported advisories or abandoned packages on 2026-11-07. It queried the standard public Composer advisory source without plugins/scripts.
- Betterleaks 1.10.0 native controls passed **5 tests**, covering allowed/prohibited/changed synthetic tokens, ignored inline suppression comments, lockfile contents, runtime errors, broken untracked symlinks, removed intermediate additions, file-type transitions and merge-only additions. The actual publishable current/index bytes and local candidate history are scanned before handoff with no suppressions. Binary/release checksums are pinned in CI/setup.
- Composer and Git distribution archives matched the exact allowlist: manifest, license, README, public source and docs. Development code, test keys, lock, tests and tooling are excluded from distribution; the lock remains committed for development verification. Public documentation links were checked locally.
- Independent read-only reviews covered Requirements, Code quality, Security and Standards compliance against the complete new package. All confirmed findings were corrected and re-reviewed. Corrections included explicit empty scopes despite global defaults, registration against an already-resolved Laravel server, distributed documentation links, replay-fixture referential integrity and secret-scan coverage of type changes/broken symlinks. There are no open findings in the reviewed package scope. No shared standards or new shared tooling changes are proposed from these package-local findings.

Only local checks have run. Remote CI/hosting protection was not exercised; no remote or package publication was performed. Consumer-owned eligibility, transaction/connection wiring, locks, rate policies and refusal audit must be checked during the separate serton-mail installation/integration. See [local installation and handoff](local-installation.md).


## Independent review disposition

All findings originated in this new package; no pre-existing repository findings were carried in.

| Direction | Fixed findings / disposition |
| --- | --- |
| Requirements | P2 explicit empty scope; P3 excluded-test documentation links; no open findings |
| Code quality | P2 explicit empty scope; P2 already-resolved server registration; no open findings |
| Security | P2 scope escalation; historical type-change hypothesis reproduced and corrected with native controls; no open findings or validation hypotheses |
| Standards compliance | P2 CI secret gate; P3 replay-fixture FK and controls; broken-symlink coverage corrected; no open findings |
