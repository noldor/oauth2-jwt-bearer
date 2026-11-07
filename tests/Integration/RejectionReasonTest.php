<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Integration;

use PDO;
use DomainException;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Noldors\OAuth2JwtBearer\AssertionRejected;
use PHPUnit\Framework\Attributes\DataProvider;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\Postgres;
use Noldors\OAuth2JwtBearer\AssertionRejectionReason;
use League\OAuth2\Server\Exception\OAuthServerException;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\RejectionCases;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\LeagueEnvironment;

final class RejectionReasonTest extends TestCase
{
    private PDO $connection;

    private LeagueEnvironment $environment;

    protected function setUp(): void
    {
        $this->connection = Postgres::connect();
        Postgres::createSchema($this->connection);
        $this->environment = new LeagueEnvironment($this->connection);
    }

    /**
     * @param array{claims?: array<string, mixed>, headers?: array<string, mixed>, raw?: string, signingKey?: string} $changes
     */
    #[DataProvider('rejections')]
    public function testLeaguePreservesStructuredReasonWithoutPublishingDetails(array $changes, string $reason): void
    {
        $assertion = RejectionCases::assertion($changes);

        try {
            $this->environment->exchange(
                $this->environment->request(['assertion' => $assertion]),
            );
            $this->fail(
                'The invalid assertion must be rejected.',
            );
        } catch (OAuthServerException $exception) {
            $this->assertSame('invalid_grant', $exception->getErrorType());
            $previous = $exception->getPrevious();
            $this->assertInstanceOf(AssertionRejected::class, $previous);
            $this->assertSame(AssertionRejectionReason::from($reason), $previous->reason);
            $expected = OAuthServerException::invalidGrant('The JWT assertion is invalid.');
            $this->assertSame($expected->getPayload(), $exception->getPayload());
            $this->assertStringNotContainsString($assertion, $previous->getMessage());
            $this->assertStringNotContainsString(
                $assertion,
                (string) $exception->generateHttpResponse(new Response())->getBody(),
            );
        }

        $this->assertSame(0, (int) Postgres::value($this->connection, 'SELECT COUNT(*) FROM league_tokens'));
        $this->assertSame(0, (int) Postgres::value($this->connection, 'SELECT COUNT(*) FROM assertion_uses'));
    }

    /**
     * @return iterable<string, array{array{claims?: array<string, mixed>, headers?: array<string, mixed>, raw?: string, signingKey?: string}, string}>
     */
    public static function rejections(): iterable
    {
        return RejectionCases::cases();
    }

    public function testExplicitSharedRejectionKeepsOriginalInstanceAndPreviousChain(): void
    {
        $cause = new DomainException('Application-owned detail.');
        $rejection = new AssertionRejected('Safe application rejection.', 42, $cause, reason: AssertionRejectionReason::CLAIMS_INVALID);
        $this->environment->resolveUser = static fn (): never => throw $rejection;

        try {
            $this->environment->exchange($this->environment->request());
            $this->fail(
                'The explicit shared rejection must become OAuth invalid_grant.',
            );
        } catch (OAuthServerException $exception) {
            $this->assertSame($rejection, $exception->getPrevious());
            $this->assertSame($cause, $rejection->getPrevious());
            $this->assertSame(42, $rejection->getCode());
            $this->assertSame(AssertionRejectionReason::CLAIMS_INVALID, $rejection->reason);
            $this->assertSame(
                OAuthServerException::invalidGrant('The JWT assertion is invalid.')->getPayload(),
                $exception->getPayload(),
            );
        }
    }

    public function testOwnSubjectExceptionPassesThroughUnchanged(): void
    {
        $failure = new DomainException('Application user/rate policy rejected the exchange.');
        $this->environment->resolveUser = static fn (): never => throw $failure;

        try {
            $this->environment->exchange($this->environment->request());
            $this->fail(
                'The application failure must propagate.',
            );
        } catch (DomainException $exception) {
            $this->assertSame($failure, $exception);
        }

        $this->assertSame(0, (int) Postgres::value($this->connection, 'SELECT COUNT(*) FROM league_tokens'));
    }

    public function testOwnUsageExceptionPassesThroughAndRollsBackBeforeRetry(): void
    {
        $failure = new DomainException('Application replay policy rejected the exchange.');
        $request = $this->environment->request();
        $this->environment->usage->afterRecord = static fn (): never => throw $failure;

        try {
            $this->environment->exchange($request);
            $this->fail(
                'The application failure must propagate.',
            );
        } catch (DomainException $exception) {
            $this->assertSame($failure, $exception);
        }

        $observer = Postgres::connect('structured-rejection-observer');
        $this->assertSame(0, (int) Postgres::value($observer, 'SELECT COUNT(*) FROM league_tokens'));
        $this->assertSame(0, (int) Postgres::value($observer, 'SELECT COUNT(*) FROM assertion_uses'));
        $this->environment->usage->afterRecord = null;
        $this->assertSame(200, $this->environment->exchange($request)->getStatusCode());
    }
}
