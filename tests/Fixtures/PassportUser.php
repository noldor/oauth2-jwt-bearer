<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Fixtures;

use Laravel\Passport\HasApiTokens;
use Illuminate\Foundation\Auth\User;
use Laravel\Passport\Contracts\OAuthenticatable;

/**
 * @property int $id
 * @property string $external_id
 * @property bool $active
 */
final class PassportUser extends User implements OAuthenticatable
{
    use HasApiTokens;

    protected $table = 'jwt_test_users';

    protected $guarded = [];

    protected $casts = ['active' => 'boolean'];
}
