<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Integration;

use PDO;
use Closure;
use RuntimeException;
use PHPUnit\Framework\TestCase;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\Postgres;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\JwtFactory;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\LeagueEnvironment;

final class PreparedLockTest extends TestCase
{
    private PDO $connection;

    private string $directory;

    /**
     * @var array<int, array{process: resource, stdout: resource, stderr: resource}>
     */
    private array $workers = [];

    protected function setUp(): void
    {
        $this->connection = Postgres::connect('race-coordinator');
        Postgres::createSchema($this->connection);
        $this->directory = \sys_get_temp_dir() . '/jwt-race-' . \bin2hex(\random_bytes(8));

        if (! \mkdir($this->directory, 0o700)) {
            throw new RuntimeException('Cannot create test directory.');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->workers as $worker) {
            \proc_terminate($worker['process']);
            \fclose($worker['stdout']);
            \fclose($worker['stderr']);
            \proc_close($worker['process']);
        }

        if ($this->connection->inTransaction()) {
            $this->connection->rollBack();
        }

        foreach (\glob($this->directory . '/*') ?: [] as $file) {
            \unlink($file);
        }

        \rmdir($this->directory);
    }

    public function testExpiresWhileActuallyWaitingForUserRowLock(): void
    {
        $this->connection->exec(
            'CREATE TABLE IF NOT EXISTS locked_users (id INTEGER PRIMARY KEY, current_time_value TIMESTAMPTZ NOT NULL)',
        );
        $this->connection->exec(
            "INSERT INTO locked_users VALUES (1, '2026-11-07T12:00:00Z') ON CONFLICT (id) DO UPDATE SET current_time_value = EXCLUDED.current_time_value",
        );
        $this->connection->beginTransaction();
        $this->connection->exec(
            "UPDATE locked_users SET current_time_value = '2026-11-07T12:01:03Z' WHERE id = 1",
        );
        $worker = $this->startWorker('jwt-user-lock');
        $this->waitForDatabaseLock('jwt-user-lock');
        $this->connection->commit();
        $this->assertSame([
            'error' => 'invalid_grant',
            'reason' => 'expired',
            'identity' => ['userId' => 'internal-7', 'clientId' => 'oauth-client'],
        ], \json_decode($this->finishWorker($worker), true, flags: \JSON_THROW_ON_ERROR));
        $this->assertSame(0, (int) Postgres::value($this->connection, 'SELECT COUNT(*) FROM league_tokens'));
    }

    private function startWorker(string $name): int
    {
        $environment = new LeagueEnvironment($this->connection);
        $body = $environment->request()->getParsedBody();
        $this->assertIsArray($body);
        $input = [
            'assertion' => $body['assertion'],
            'publicKeyBase64' => \base64_encode(JwtFactory::keys('ed25519:crm')['public']),
            'signingKey' => JwtFactory::keys('oauth')['private'],
            'name' => $name,
        ];
        $path = $this->directory . '/' . $name . '.json';
        \file_put_contents($path, \json_encode($input, \JSON_THROW_ON_ERROR));
        $process = \proc_open([\PHP_BINARY, __DIR__ . '/../Fixtures/exchange-worker.php', $path], [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ], $pipes);

        if (! \is_resource($process)) {
            throw new RuntimeException('Cannot launch exchange worker.');
        }

        \fclose($pipes[0]);
        $this->workers[] = ['process' => $process, 'stdout' => $pipes[1], 'stderr' => $pipes[2]];

        return \array_key_last($this->workers);
    }

    private function finishWorker(int $index): string
    {
        $worker = $this->workers[$index];
        $output = \stream_get_contents($worker['stdout']);
        $errors = \stream_get_contents($worker['stderr']);
        \fclose($worker['stdout']);
        \fclose($worker['stderr']);
        $exit = \proc_close($worker['process']);
        unset($this->workers[$index]);
        $this->assertSame('', $errors);
        $this->assertSame(0, $exit);

        return $output;
    }

    private function waitForDatabaseLock(string $application): void
    {
        $statement = $this->connection->prepare(
            "SELECT COUNT(*) FROM pg_stat_activity WHERE application_name = ? AND wait_event_type = 'Lock' AND cardinality(pg_blocking_pids(pid)) > 0",
        );
        $this->waitUntil(
            function () use ($statement, $application): bool {
                $this->connection->query('SELECT pg_stat_clear_snapshot()');
                $statement->execute([$application]);

                return (int) $statement->fetchColumn() === 1;
            },
        );
    }

    /**
     * @param Closure(): bool $condition
     */
    private function waitUntil(Closure $condition): void
    {
        $deadline = \microtime(true) + 8;

        while (! $condition()) {
            if (\microtime(true) > $deadline) {
                $this->fail(
                    'Timed out waiting for the coordinated database race.',
                );
            }

            \usleep(10_000);
        }
    }
}
