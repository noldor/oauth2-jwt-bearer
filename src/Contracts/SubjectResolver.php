<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Contracts;

use Noldors\OAuth2JwtBearer\VerifiedAssertion;

interface SubjectResolver
{
    /**
     * Resolve an existing, eligible user; acquire application locks here if necessary.
     * Own application exceptions propagate unchanged. AssertionRejected opts into OAuth invalid_grant.
     *
     * @return string local user identifier; empty results are rejected by the grant
     *
     * @throws \Noldors\OAuth2JwtBearer\AssertionRejected
     */
    public function resolve(VerifiedAssertion $assertion): string;
}
