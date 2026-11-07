<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Fixtures;

use League\OAuth2\Server\Entities\Traits\ScopeTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\ScopeEntityInterface;

final class LeagueScope implements ScopeEntityInterface
{
    use EntityTrait;
    use ScopeTrait;

    /**
     * @param non-empty-string $identifier
     */
    public function __construct(string $identifier)
    {
        $this->setIdentifier($identifier);
    }
}
