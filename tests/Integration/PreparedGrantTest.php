<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Integration;

use PDO;
use Throwable;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Noldors\OAuth2JwtBearer\JwtBearerGrant;
use Psr\Http\Message\ServerRequestInterface;
use League\OAuth2\Server\AuthorizationServer;
use Noldors\OAuth2JwtBearer\AssertionRejected;
use Noldors\OAuth2JwtBearer\VerifiedAssertion;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\Postgres;
use Noldors\OAuth2JwtBearer\AssertionRejectionReason;
use League\OAuth2\Server\Exception\OAuthServerException;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\OAuthResponse;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\RejectionCases;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\LeagueEnvironment;

final class PreparedGrantTest extends TestCase
{
    private PDO $connection;

    private LeagueEnvironment $environment;

    private AuthorizationServer $base;

    protected function setUp(): void
    {
        $this->connection = Postgres::connect();
        Postgres::createSchema($this->connection);
        $this->environment = new LeagueEnvironment($this->connection);
        $this->base = $this->environment->server();
    }

    public function testPreparedGrantUsesTrustedLocalIdAndIgnoresHttpUserId(): void
    {
        $request = $this->environment->request(['user_id' => 'attacker-id', 'scope' => 'read'])->withAttribute(
            'user_id',
            'another-attacker',
        );
        $assertion = $this->verified($request);
        $server = clone $this->base;
        $server->enableGrantType(
            JwtBearerGrant::forVerifiedAssertion($this->environment->verifier, $assertion, 'local-987'),
        );
        $response = $this->respond($server, $request);
        $token = OAuthResponse::token(
            OAuthResponse::body($response)['access_token'],
        );
        $this->assertSame('local-987', $token->claims()->get('sub'));
        $this->assertSame('local-987', Postgres::value($this->connection, 'SELECT user_id FROM league_tokens'));
        $this->assertSame(1, $this->environment->keyResolutions);
        $this->assertSame('external-42', $assertion->subject);
        $this->assertSame(['read'], $token->claims()->get('scopes'));
    }

    public function testEachPreparedCloneKeepsItsOwnIdentityAndBaseStaysRaw(): void
    {
        $request = $this->environment->request();
        $assertion = $this->verified($request);

        foreach (['local-7', 'local-8'] as $localId) {
            $server = clone $this->base;
            $server->enableGrantType(
                JwtBearerGrant::forVerifiedAssertion($this->environment->verifier, $assertion, $localId),
            );
            $body = OAuthResponse::body($this->respond($server, $request));
            $this->assertSame($localId, OAuthResponse::token($body['access_token'])->claims()->get('sub'));
        }

        $body = OAuthResponse::body($this->respond($this->base, $request));
        $this->assertSame('external-42', OAuthResponse::token($body['access_token'])->claims()->get('sub'));
    }

    public function testPreparedGrantRejectsAnotherValidRequestAssertion(): void
    {
        $request = $this->environment->request();
        $server = clone $this->base;
        $server->enableGrantType(
            JwtBearerGrant::forVerifiedAssertion($this->environment->verifier, $this->verified($request), 'local-7'),
        );
        $changed = $this->environment->request([
            'assertion' => RejectionCases::assertion(['claims' => ['sub' => 'other-external']]),
        ]);
        $this->assertRejected($server, $changed, AssertionRejectionReason::INVALID_ASSERTION);
    }

    public function testPreparedGrantRejectsWhitespaceAroundTheVerifiedAssertion(): void
    {
        $request = $this->environment->request();
        $verified = $this->verified($request);
        $body = (array) $request->getParsedBody();
        $server = clone $this->base;
        $server->enableGrantType(
            JwtBearerGrant::forVerifiedAssertion($this->environment->verifier, $verified, 'local-7'),
        );

        foreach ([' ' . $verified->token->toString(), $verified->token->toString() . ' '] as $changed) {
            $this->assertRejected(
                $server,
                $request->withParsedBody([...$body, 'assertion' => $changed]),
                AssertionRejectionReason::INVALID_ASSERTION,
            );
        }
    }

    public function testPreparedPathUsesTrustedVerificationWithoutResolvingKeysAgain(): void
    {
        $request = $this->environment->request();
        $assertion = $this->verified($request);
        $before = $this->environment->keyResolutions;
        $server = clone $this->base;
        $server->enableGrantType(
            JwtBearerGrant::forVerifiedAssertion($this->environment->verifier, $assertion, 'local-7'),
        );
        $this->assertSame(200, $this->respond($server, $request)->getStatusCode());
        $this->assertSame($before, $this->environment->keyResolutions);
        $this->respond($this->base, $request);
        $this->assertSame($before + 1, $this->environment->keyResolutions);
    }

    public function testPreparedGrantRechecksExpiryAfterApplicationWork(): void
    {
        $request = $this->environment->request();
        $assertion = $this->verified($request);
        $this->environment->clock->time = $this->environment->clock->time->modify('+63 seconds');
        $server = clone $this->base;
        $server->enableGrantType(
            JwtBearerGrant::forVerifiedAssertion($this->environment->verifier, $assertion, 'local-7'),
        );
        $this->assertRejected($server, $request, AssertionRejectionReason::EXPIRED);
    }

    private function verified(ServerRequestInterface $request): VerifiedAssertion
    {
        $body = $request->getParsedBody();
        $this->assertIsArray($body);
        $this->assertIsString($body['assertion']);

        return $this->environment->verifier->verify($body['assertion']);
    }

    private function respond(AuthorizationServer $server, ServerRequestInterface $request): ResponseInterface
    {
        $this->connection->beginTransaction();

        try {
            $response = $server->respondToAccessTokenRequest($request, new Response());
            $this->connection->commit();

            return $response;
        } catch (Throwable $exception) {
            $this->connection->rollBack();

            throw $exception;
        }
    }

    private function assertRejected(AuthorizationServer $server, ServerRequestInterface $request, AssertionRejectionReason $reason): void
    {
        try {
            $this->respond($server, $request);
            $this->fail(
                'Prepared issuance must reject this assertion.',
            );
        } catch (OAuthServerException $exception) {
            $this->assertSame('invalid_grant', $exception->getErrorType());
            $cause = $exception->getPrevious();
            $this->assertInstanceOf(AssertionRejected::class, $cause);
            $this->assertSame($reason, $cause->reason);
        }

        $this->assertSame(0, (int) Postgres::value($this->connection, 'SELECT COUNT(*) FROM league_tokens'));
    }
}
