<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Integration;

use PDO;
use PDOException;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\Postgres;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\LeagueEnvironment;

final class AssertionUsageConstraintTest extends TestCase
{
    private PDO $connection;

    protected function setUp(): void
    {
        $this->connection = Postgres::connect();
        Postgres::createSchema($this->connection);
    }

    public function testUsageCannotReferenceMissingToken(): void
    {
        try {
            $this->connection->exec(
                "INSERT INTO assertion_uses VALUES ('crm', 'once', 'missing-token', '2026-11-07T12:01:03Z')",
            );
            $this->fail(
                'The foreign key must reject an orphan usage.',
            );
        } catch (PDOException $exception) {
            $this->assertSame('23503', $exception->getCode());
        }

        $this->assertSame(0, (int) Postgres::value($this->connection, 'SELECT COUNT(*) FROM assertion_uses'));
    }

    #[DataProvider('referentialChanges')]
    public function testReferencedTokenCannotBeDeletedOrReidentified(string $sql): void
    {
        $environment = new LeagueEnvironment($this->connection);
        $environment->exchange($environment->request());

        try {
            $this->connection->exec($sql);
            $this->fail(
                'The foreign key must preserve the replay record link.',
            );
        } catch (PDOException $exception) {
            $this->assertSame('23503', $exception->getCode());
        }

        $this->assertSame(
            1,
            (int) Postgres::value(
                $this->connection,
                'SELECT COUNT(*) FROM assertion_uses u JOIN league_tokens t ON t.id = u.token_id',
            ),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function referentialChanges(): iterable
    {
        yield 'delete restriction' => ['DELETE FROM league_tokens'];

        yield 'update restriction' => ["UPDATE league_tokens SET id = 'changed-token'"];
    }
}
