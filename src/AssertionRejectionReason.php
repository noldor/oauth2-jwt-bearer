<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer;

enum AssertionRejectionReason: string
{
    case INVALID_ASSERTION = 'invalid_assertion';
    case KEY_UNKNOWN = 'key_unknown';
    case ALGORITHM_INVALID = 'algorithm_invalid';
    case SIGNATURE_INVALID = 'signature_invalid';
    case CLAIMS_INVALID = 'claims_invalid';
    case EXPIRED = 'expired';
    case NOT_YET_VALID = 'not_yet_valid';
}
