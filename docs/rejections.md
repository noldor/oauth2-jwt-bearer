# Structured assertion rejection and application audit

`AssertionRejected` exposes the readonly enum property `reason: AssertionRejectionReason`. A grant rejection still produces League's standard `OAuthServerException` with `error: invalid_grant`, HTTP 400 and the same generic payload for every assertion reason. The original `AssertionRejected` instance is available through `getPrevious()`; it is not discarded or replaced with a parsed message.

```php
use League\OAuth2\Server\Exception\OAuthServerException;
use Noldors\OAuth2JwtBearer\AssertionRejected;
use Noldors\OAuth2JwtBearer\AssertionRejectionReason;

try {
    $response = $connection->transaction(
        fn () => $server->respondToAccessTokenRequest($request, $responsePrototype)
    );
} catch (OAuthServerException|AssertionRejected $exception) {
    $rejection = $exception instanceof AssertionRejected ? $exception : $exception->getPrevious();
    if ($rejection instanceof AssertionRejected) {
        $reason = $rejection->reason;
        // Map $reason to the application's audit taxonomy after rollback.
        // Keep the established per-exchange User/client context from its resolver.
    }
    throw $exception;
}
```

The example's connection wrapper belongs to the application. When using PDO directly, use the explicit begin/commit/rollback boundary shown in [League integration](league.md). Catch outside the transaction: converting rejection into a successful callback result could commit partial token/use writes.

## Stable reasons

| Enum case / value | Meaning |
| --- | --- |
| `INVALID_ASSERTION` / `invalid_assertion` | JWT decoding/compact-structure failure, unsupported critical header, or a generic application `AssertionRejected` without a more specific reason |
| `KEY_UNKNOWN` / `key_unknown` | Missing/invalid `kid`, or the trusted issuer-scoped key resolver returns no key |
| `ALGORITHM_INVALID` / `algorithm_invalid` | Unsupported/disallowed `alg`, or the resolved key is bound to another algorithm |
| `SIGNATURE_INVALID` / `signature_invalid` | Cryptographic signature verification failed |
| `CLAIMS_INVALID` / `claims_invalid` | Untrusted issuer; missing/invalid claims, audience, lifetime or extra claim constraint; empty resolved user ID; a claim required by the configured profile |
| `EXPIRED` / `expired` | Expiration is reached after applying the configured leeway |
| `NOT_YET_VALID` / `not_yet_valid` | `iat` or `nbf` is later than the current time plus leeway |

Basic JSON claim-type checks precede the JWT library's normalization of NumericDate and audience. They establish no trusted identity. Signature/issuer/audience/time validation and native client resolution all complete before the application subject resolver is invoked. Additional Lcobucci claim constraints are still evaluated only after signature verification. When several defects coexist, the first reached rejection wins; the reason does not prove that later checks succeeded.

An application can map these general reasons to existing audit values such as `assertion_invalid`, `key_unknown`, `signature_invalid`, `claims_invalid` and `assertion_expired`. For example, both algorithm and signature failures may map to `signature_invalid`; the application chooses its historical category for `NOT_YET_VALID`. These application audit strings are not built into the grant. Do not parse exception text or repeat JWT parsing/signature verification in the consumer.

## Preserve trusted User/client context after waits

The application subject resolver can retain its existing User/model and the verified mapped client ID in an **invocation-local application context**. Populate it only after finding/locking an eligible user. The resolver receives `VerifiedAssertion`, and the grant has already resolved/authenticated its configured client before invoking it. The package never stores, resets or reconstructs that context and knows no domain User or audit service.

If assertion time expires after subject/scope work or native token persistence, the grant throws `invalid_grant` with `AssertionRejected::reason === EXPIRED` in its previous chain. If the application’s later replay insert waits, its own call to public `assertValidAt()` throws `AssertionRejected` directly, because that work is after the native grant response. Both paths expose the same structured reason; the application handles them at its own boundary. The application context remains available after issuance rollback, so refusal audit can use the already-established trusted User/client. Capture the relevant identity snapshot at resolution; do not derive an identity by reparsing an invalid assertion or by querying a different user during error handling. Keep the context out of shared singleton/static state so one exchange cannot inherit another exchange's identity. Initial verification failures must not populate it.

Native League and Passport tests exercise the grant and application-owned wrapper separately. Coordinated PostgreSQL workers also verify the reason and retained local identity after actual user-row lock waits and replay-insert contention, with all token/use writes rolled back.

## Exception and information boundaries

Application-owned exceptions from `SubjectResolver` or trusted key/configuration infrastructure propagate as the same throwable. Replay SQL and its exceptions live in the application issuance operation after the native response and are never intercepted by the grant. Rate limits, missing/deleted users and application replay exceptions keep their own types, codes and safe metadata; the grant does not catch arbitrary `Throwable`. An application that deliberately throws `AssertionRejected` opts into the shared OAuth rejection conversion and may supply a reason explicitly:

```php
throw new AssertionRejected(
    'The application rejected this assertion.',
    reason: AssertionRejectionReason::CLAIMS_INVALID,
);
```

The constructor retains the normal RuntimeException message/code/previous arguments; existing calls remain valid and default to `INVALID_ASSERTION`. The grant preserves this exception instance and its explicit previous chain. Unexpected token persistence/signing failures still propagate and the application's full-response transaction must roll back.

Package-created rejection messages are constant safe descriptions. The grant does not expose the reason, decoded claims, raw assertion, key material or vendor diagnostic text in the OAuth payload. Parser/constraint errors are normalized without chaining potentially input-bearing vendor messages. If the application supplies its own exception messages/previous errors or logs whole requests/traces, it owns their redaction. No success audit is added.
