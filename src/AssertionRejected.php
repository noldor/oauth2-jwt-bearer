<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer;

use Throwable;
use RuntimeException;

final class AssertionRejected extends RuntimeException
{
    public function __construct(
        string $message = 'The JWT assertion is invalid.',
        int $code = 0,
        Throwable|null $previous = null,
        public readonly AssertionRejectionReason $reason = AssertionRejectionReason::INVALID_ASSERTION,
    ) {
        parent::__construct($message, $code, $previous);
    }
}
