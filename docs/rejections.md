# Structured assertion rejection and application errors

`AssertionRejected` exposes readonly `reason: AssertionRejectionReason`. Inside the grant it is wrapped in native `OAuthServerException` with `invalid_grant`, HTTP 400 and a generic assertion-error payload; the original exception remains in `getPrevious()`. A direct application call to `verify()` or `assertValidAt()` throws `AssertionRejected` directly.

Catch outside the complete transaction:

```php
try {
    $response = $application->issue($assertion);
} catch (\League\OAuth2\Server\Exception\OAuthServerException|\Noldors\OAuth2JwtBearer\AssertionRejected $exception) {
    $rejection = $exception instanceof \Noldors\OAuth2JwtBearer\AssertionRejected
        ? $exception : $exception->getPrevious();
    if ($rejection instanceof \Noldors\OAuth2JwtBearer\AssertionRejected) {
        $reason = $rejection->reason;
        // Application refusal-audit mapping after rollback.
    }
    throw $exception;
}
```

## Stable reasons

| Enum / value | Meaning |
| --- | --- |
| `INVALID_ASSERTION` / `invalid_assertion` | Compact/JSON structure failure, unsupported critical header, prepared/request assertion mismatch, or generic rejection |
| `KEY_UNKNOWN` / `key_unknown` | Missing/invalid `kid` or no trusted issuer-scoped key |
| `ALGORITHM_INVALID` / `algorithm_invalid` | Unsupported/disallowed algorithm or algorithm/key-binding mismatch |
| `SIGNATURE_INVALID` / `signature_invalid` | Cryptographic signature failure |
| `CLAIMS_INVALID` / `claims_invalid` | Untrusted issuer, missing/invalid claims, audience, lifetime or extra constraint |
| `EXPIRED` / `expired` | Expiration reached with configured leeway |
| `NOT_YET_VALID` / `not_yet_valid` | `iat` or `nbf` exceeds current time plus leeway |

Basic JSON type checks precede JWT-library date/audience normalization and establish no trusted identity. Additional claim constraints run after signature verification. The first reached failure wins; a reason does not prove later checks succeeded. An empty trusted local ID is a programmer error (`InvalidArgumentException`), not a claim failure.

## Identity and timing

For an external subject, the application first verifies and then finds/locks its eligible local User. Keep the verified assertion, mapped client and User in ordinary invocation-local variables. The package has no resolver, callback or application context object. Native client authentication occurs during the subsequent prepared native request; before it succeeds, the profile's mapped client ID is configuration, not proof of supplied client credentials.

The prepared API accepts the actual snapshot returned by the same verifier and the trusted local ID. It does no second signature/key lookup. It checks exact original JWT bytes and fresh time, including after application lock waits; the grant checks again before/after persistence. The application performs a final public `assertValidAt($verified)` after the complete response and before commit. That last call throws directly; grant-side expiry is wrapped as `invalid_grant`. Both expose `EXPIRED`.

If a post-lock time check fails, already-established local identity variables remain usable for refusal audit after rollback. Do not reparse an invalid JWT or query a different user to reconstruct identity. Initial verification failure establishes no trusted User. Do not place per-invocation identity in singleton/static state. The real PostgreSQL worker test verifies lock-wait expiry and retained identity with no persisted token.

## Error boundaries

Application user/rate/database errors occur in its own operation and retain their own types/codes; they are not JWT validation failures. Trusted key/configuration infrastructure failures and unexpected token persistence/signing failures propagate. The grant catches only `AssertionRejected`, not arbitrary `Throwable`. No success audit is added.

The exception constructor preserves normal RuntimeException message/code/previous arguments, with optional `reason` defaulting to `INVALID_ASSERTION`. Package rejection messages are constant safe descriptions. The OAuth payload does not expose reasons, decoded claims, raw assertions, keys or vendor diagnostics. Parser/constraint failures are normalized without chaining input-bearing vendor messages. The application owns redaction of its own messages, previous errors, requests and traces.
