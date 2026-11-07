# Transaction and replay contract

The application owns one transaction around **the entire `AuthorizationServer::respondToAccessTokenRequest()` call**, not just the grant or access-token repository. League persists the token inside the grant and signs it later in `generateHttpResponse()`, before the AuthorizationServer returns. A failed response/signature must roll back every required write.

All participating repositories and the locked user must use the same transaction/connection. A second database connection, Redis reservation or after-commit insert cannot establish this SQL atomicity guarantee. A replay implementation on a different store must document its own guarantees; the package does not promise cross-store transactions.

## Execution order

1. Parse the assertion, resolve its configured issuer/key and verify its signature and claims without writing.
2. Resolve the configured OAuth client and validate any supplied credentials; validate requested scopes through League.
3. The application subject resolver acquires its user lock, checks current eligibility and returns the internal ID. Scope finalization uses that ID and the mapped client.
4. Recheck assertion time using a fresh PSR-clock reading after application resolution/scope finalization.
5. League creates and persists the access token through its normal access-token repository.
6. The application usage repository atomically inserts the assertion-use identity and token link. A duplicate raises `AssertionRejected`; an unavailable store raises its real operational error.
7. Recheck assertion time after possible contention in the usage insert. Set the normal bearer response and emit the native League access-token event.
8. League serializes/signs the access token and returns the standard response. Only then does the application commit.

The package emits no application audit. Native Passport `AccessTokenCreated` and League issuance events are normal framework events; they occur before transaction commit. Applications must account for that timing in their own listeners and must not use successful-issuance events to create a success audit for the agreed serton-mail flow. Refusal audit and rate limits remain application concerns.

## Atomic SQL example

The following is an application-owned PostgreSQL example, not a package migration. Choose your own table/model names and retention policy. For Passport, `token_id` references its existing `oauth_access_tokens.id`:

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

`record()` performs a single conditional insert, not a prior existence check:

```php
$statement = $connection->prepare(
    'INSERT INTO assertion_uses (issuer, jti, token_id, expires_at)
     VALUES (?, ?, ?, ?) ON CONFLICT (issuer, jti) DO NOTHING'
);
$validUntil = $assertion->expiresAt->add(
    new DateInterval('PT' . $assertion->issuer->requirements->leewaySeconds . 'S')
);
$statement->execute([
    $assertion->issuer->issuer,
    $assertion->id,
    $token->getIdentifier(),
    $validUntil->format('Y-m-d H:i:s.uP'),
]);
if ($statement->rowCount() !== 1) {
    throw new AssertionRejected('Assertion has already been consumed.');
}
```

Keep records at least until `exp + leeway`, including during key rotation. Avoid deleting a record while its assertion can still be accepted. If token retention requires deleting tokens earlier, choose a deliberate relationship/retention design that preserves replay protection. Never silently cascade replay records away while their assertions remain usable.

At PostgreSQL's default READ COMMITTED isolation, a competing insert on the unique key waits for the first transaction. If it commits, the second insert affects zero rows and the enclosing transaction rolls back its token. If the first rolls back, the second can insert and succeed if the assertion is still valid. At stronger isolation, the application may need to retry the entire transaction on a serialization failure; each retry must rerun the real grant/time checks.

The fixtures SqlAssertionUsage (`tests/Fixtures/SqlAssertionUsage.php` in the source checkout) and ConcurrentExchangeTest (`tests/Integration/ConcurrentExchangeTest.php` in the source checkout) demonstrate the contract. Independent worker processes enter an observed PostgreSQL lock wait, produce exactly one committed token/use pair, and test expiration while actually waiting for a user row lock. Rollback tests observe state through another connection before retrying the same assertion.
