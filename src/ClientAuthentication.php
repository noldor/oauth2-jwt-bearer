<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer;

enum ClientAuthentication
{
    case REQUIRED;
    case OPTIONAL;
}
