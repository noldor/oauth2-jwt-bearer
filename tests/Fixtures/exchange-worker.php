<?php

declare(strict_types = 1);

use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Noldors\OAuth2JwtBearer\JwtBearerGrant;
use Noldors\OAuth2JwtBearer\AssertionRejected;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\Postgres;
use League\OAuth2\Server\Exception\OAuthServerException;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\LeagueEnvironment;

require __DIR__ . '/../../vendor/autoload.php';

/** @var list<string> $argv */
$path = $argv[1] ?? throw new RuntimeException('Missing input file.');
$json = \file_get_contents($path);

if (false === $json) {
    throw new RuntimeException('Cannot read worker input.');
}

/** @var array{assertion: string, publicKeyBase64: non-empty-string, signingKey: string, name: string} $input */
$input = \json_decode($json, true, flags: \JSON_THROW_ON_ERROR);
$environment = new LeagueEnvironment(Postgres::connect($input['name']));
$publicKey = \base64_decode($input['publicKeyBase64'], true);

if (false === $publicKey || '' === $publicKey) {
    throw new RuntimeException('Invalid encoded public key.');
}

$environment->verificationKey = $publicKey;
$environment->signingKey = $input['signingKey'];
$base = $environment->server();
$request = new ServerRequest('POST', 'https://oauth.example/token')->withParsedBody([
    'grant_type' => JwtBearerGrant::IDENTIFIER,
    'assertion' => $input['assertion'],
]);
$identity = null;
$environment->connection->beginTransaction();

try {
    $verified = $environment->verifier->verify($input['assertion']);
    $time = Postgres::value($environment->connection, 'SELECT current_time_value FROM locked_users WHERE id = 1 FOR UPDATE');

    if (! \is_string($time)) {
        throw new RuntimeException('Missing locked user time.');
    }

    $environment->clock->time = new DateTimeImmutable($time);
    $identity = ['userId' => 'internal-7', 'clientId' => $verified->issuer->clientId];
    $server = clone $base;
    $server->enableGrantType(
        JwtBearerGrant::forVerifiedAssertion($environment->verifier, $verified, $identity['userId']),
    );
    $server->respondToAccessTokenRequest($request, new Response());
    $environment->verifier->assertValidAt($verified);
    $environment->connection->commit();
    \fwrite(\STDOUT, 'success');
} catch (Throwable $exception) {
    $environment->connection->rollBack();

    if (! $exception instanceof OAuthServerException) {
        throw $exception;
    }

    $previous = $exception->getPrevious();
    \fwrite(\STDOUT, \json_encode([
        'error' => $exception->getErrorType(),
        'reason' => $previous instanceof AssertionRejected ? $previous->reason->value : null,
        'identity' => $identity,
    ], \JSON_THROW_ON_ERROR));
}
