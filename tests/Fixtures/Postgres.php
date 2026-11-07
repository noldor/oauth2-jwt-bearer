<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Fixtures;

use PDO;
use RuntimeException;

final class Postgres
{
    public static function connect(string $application = 'jwt-bearer-tests'): PDO
    {
        $host = \getenv('DB_HOST') ?: 'postgres';
        $port = \getenv('DB_PORT') ?: '5432';
        $database = \getenv('DB_DATABASE') ?: 'oauth2_jwt_bearer_testing';
        $connection = new PDO("pgsql:host={$host};port={$port};dbname={$database}", \getenv('DB_USERNAME') ?: 'packages', \getenv('DB_PASSWORD') ?: '', [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        ]);
        $statement = $connection->prepare(
            "SELECT set_config('application_name', ?, false)",
        );
        $statement->execute([$application]);
        $connection->exec("SET statement_timeout = '10s'");

        return $connection;
    }

    public static function value(PDO $connection, string $sql): bool|int|string|null
    {
        $statement = $connection->query($sql);

        if (false === $statement) {
            throw new RuntimeException('Query failed.');
        }

        return $statement->fetchColumn();
    }

    public static function createSchema(PDO $connection): void
    {
        $connection->exec('DROP TABLE IF EXISTS league_tokens');
        $connection->exec(
            'CREATE TABLE league_tokens (id VARCHAR(80) PRIMARY KEY, user_id TEXT, client_id TEXT NOT NULL, scopes JSONB NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE)',
        );
    }
}
