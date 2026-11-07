# Application transaction and local user mapping

The application operation owns user eligibility, rate rules, row locks and the SQL transaction. There is no assertion-use table, one-time check or subject resolver. Repeating a valid assertion intentionally creates another access token.

For an external subject, keep this sequence in one transaction:

1. Verify the original JWT through `AssertionVerifier::verify()`.
2. Apply application rules, find/lock the existing local user and check current eligibility.
3. Prepare a fresh grant using the verified snapshot and trusted local user ID; register it on a local clone of the native server.
4. Generate the complete native response, including persistence and signing. The grant checks time before and after native token persistence.
5. Call public `assertValidAt()` after the full response, before commit. This checks time only and covers later waiting/work.
6. Commit and return the response.

Token persistence, required application writes and user locks must share a connection. With Passport, account for `passport.connection` and custom token models. Any persistence/signing/SQL/time failure must escape the transaction and roll back. Do not catch an error inside a transaction callback and return it as a successful result. Native token events retain their normal pre-commit timing.

A PDO example; the application replaces the marked line with its direct SQL/domain operation:

```php
$connection->beginTransaction();
try {
    $verified = $verifier->verify($assertion);
    // Find/lock/check the application's existing User here; no package callback.
    $user = $users->findAndLockEligible($verified->issuer->issuer, $verified->subject);
    $server = clone $authorizationServer;
    $server->enableGrantType(
        \Noldors\OAuth2JwtBearer\JwtBearerGrant::forVerifiedAssertion(
            $verifier, $verified, (string) $user->id,
        ),
        new DateInterval('PT1H'),
    );
    $response = $server->respondToAccessTokenRequest($request, new \Nyholm\Psr7\Response());
    $verifier->assertValidAt($verified);
    $connection->commit();
} catch (Throwable $exception) {
    if ($connection->inTransaction()) {
        $connection->rollBack();
    }
    throw $exception;
}
```

`$request` must contain the exact original assertion. Pass the actual verified object from the same configured verifier. The prepared API trusts host PHP code and local ID; it adds no second crypto, opaque proof or mutable global context. It binds original bytes, retains verified issuer/subject/profile and rechecks time after lock waits. Keep `$verified`, `$user` and `$server` local to each invocation.

Rollback leaves no issued token. A retry can proceed while the assertion is valid. A lost connection during COMMIT can leave an unknown outcome; losing the response after commit does not undo issuance. There is no exact-response recovery/idempotency promise.

The raw grant is for an already local `sub`. Do not expose it for external CRM IDs on the shared server. See [Passport](passport.md). Actual examples/tests are in `tests/Integration/PreparedGrantTest.php`, `PreparedLockTest.php` and `PassportGrantTest.php` in the source checkout.
