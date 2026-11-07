<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Fixtures;

use League\OAuth2\Server\Entities\Traits\ClientTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\ClientEntityInterface;

final class LeagueClient implements ClientEntityInterface
{
    use ClientTrait;
    use EntityTrait;

    /**
     * @param non-empty-string $identifier
     */
    public function __construct(string $identifier)
    {
        $this->setIdentifier($identifier);
        $this->isConfidential = true;
    }
}
