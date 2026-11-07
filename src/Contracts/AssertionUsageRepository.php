<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Contracts;

use Noldors\OAuth2JwtBearer\VerifiedAssertion;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;

interface AssertionUsageRepository
{
    /**
     * Atomically record (issuer, jti) and the token in the issuance transaction.
     * Reject duplicates with AssertionRejected. Retain the record through exp + leeway.
     * The caller must wrap the entire AuthorizationServer response, including signing,
     * in a transaction shared by token persistence, user locks and this repository.
     *
     * @throws \Noldors\OAuth2JwtBearer\AssertionRejected
     */
    public function record(VerifiedAssertion $assertion, AccessTokenEntityInterface $token): void;
}
