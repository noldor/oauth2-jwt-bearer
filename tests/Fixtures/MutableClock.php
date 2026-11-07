<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Fixtures;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

final class MutableClock implements ClockInterface
{
    public function __construct(
        public DateTimeImmutable $time = new DateTimeImmutable('2026-11-07T12:00:00Z'),
    ) {}

    public function now(): DateTimeImmutable
    {
        return $this->time;
    }
}
