# Application-owned transaction and replay example

The package verifies assertions and issues standard League/Passport tokens. It neither records assertion use nor supplies a storage/replay callback. The complete application issuance operation (for example, `Token::issue`) owns any replay policy, SQL, exceptions and transaction.

Wrap **the entire `AuthorizationServer::respondToAccessTokenRequest()` call and the application's later replay insert/time check** in one transaction. League persists the token inside the grant and signs it while generating the native response. A persistence/signature/SQL/time failure must roll back all required writes. Use the same connection for Passport token persistence, user row locks and the application replay insert.

## Order and responsibilities

1. The application opens its transaction and creates invocation-local context.
2. The grant verifies the assertion, resolves/authenticates its configured client and validates scopes.
3. The application `SubjectResolver` finds/locks an eligible user, retains the already-verified `VerifiedAssertion` and trusted User/client context, then returns the internal user ID.
4. The grant finalizes scopes and rechecks assertion time with a fresh PSR-clock reading.
5. League creates/persists the access token through its normal repository. The grant rechecks time after that persistence.
6. The grant sets the normal bearer response and emits the native League event. AuthorizationServer serializes/signs the token and returns the response, still inside the application's transaction.
7. The application obtains the issued token ID from its trusted native response/result, then atomically inserts `(issuer, jti)` linked to that token. A duplicate key is handled by the application's replay policy and exception.
8. Because the insert can wait, the application calls the public `AssertionVerifier::assertValidAt($context->assertion)` again. This uses the original verified assertion, without reparsing or verifying the assertion JWT again.
9. Only then does the application commit and return the response.

The package emits no application audit. Native Passport/League token events retain their normal timing before application commit. The consuming application handles refusal audit after rollback and does not add success audit for the agreed serton-mail flow.

## Concrete SQL example in the application operation

This PostgreSQL schema is an illustrative application-owned choice, not a package migration or required package schema:

```sql
CREATE TABLE assertion_uses (
    issuer TEXT NOT NULL,
    jti TEXT NOT NULL,
    token_id CHAR(80) NOT NULL REFERENCES oauth_access_tokens(id)
        ON DELETE RESTRICT ON UPDATE RESTRICT,
    expires_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    PRIMARY KEY (issuer, jti)
);
```

The following code belongs directly in the application's complete issuance operation. `$context->assertion` was retained by its subject resolver during this invocation; `$verifier` is the same configured verifier used by the grant. No package repository/service is needed:

```php
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Nyholm\Psr7\Response;

$connection->beginTransaction();
try {
    $response = $authorizationServer->respondToAccessTokenRequest($request, new Response());
    $assertion = $context->assertion;

    // Read jti from our own server-issued access token, not from a new
    // verification of the untrusted assertion. An existing application
    // response DTO may already provide this native token identifier.
    $body = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
    $issuedToken = (new Parser(new JoseEncoder()))->parse($body['access_token']);
    if (!$issuedToken instanceof UnencryptedToken) {
        throw new LogicException('Expected the native signed access token.');
    }
    $tokenId = $issuedToken->claims()->get('jti');

    $validUntil = $assertion->expiresAt->add(
        new DateInterval('PT' . $assertion->issuer->requirements->leewaySeconds . 'S')
    );
    $statement = $connection->prepare(
        'INSERT INTO assertion_uses (issuer, jti, token_id, expires_at)
         VALUES (?, ?, ?, ?) ON CONFLICT (issuer, jti) DO NOTHING'
    );
    $statement->execute([
        $assertion->issuer->issuer,
        $assertion->id,
        $tokenId,
        $validUntil->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\\TH:i:s.uP'),
    ]);
    if ($statement->rowCount() !== 1) {
        throw new ApplicationReplayRejected();
    }

    $verifier->assertValidAt($assertion);
    $connection->commit();
    return $response;
} catch (Throwable $exception) {
    $connection->rollBack();
    throw $exception;
}
```

`ApplicationReplayRejected` and the context are application-owned types in this example. The application determines the duplicate-key error representation and audit mapping. A time failure from the public verifier here is a direct `AssertionRejected` with its structured reason; it is outside the grant's OAuth wrapper. Handle it through the application's normal error boundary, without committing the failed callback.

Keep replay records through at least `exp + leeway`, including key rotation. Do not delete a record while its assertion can still be accepted. Coordinate token/record retention deliberately. With PostgreSQL READ COMMITTED, a competing unique insert waits: a committed winner causes replay rejection; a rolled-back winner lets another still-valid exchange proceed. Stronger isolation can require retrying the whole application transaction, including fresh verification/time checks.

The application examples in `tests/Fixtures/LeagueEnvironment.php` and `tests/Integration/PassportGrantTest.php` contain their own SQL after the native response. `tests/Integration/ConcurrentExchangeTest.php` observes actual PostgreSQL waits and verifies one successful application exchange, rollback and post-insert expiry. Direct native-grant tests separately prove that the grant writes no replay record and can exchange the same assertion again within its validity window.
