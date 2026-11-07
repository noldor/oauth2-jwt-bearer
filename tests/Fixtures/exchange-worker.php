<?php

declare(strict_types = 1);

use Nyholm\Psr7\ServerRequest;
use Noldors\OAuth2JwtBearer\AssertionRejected;
use Noldors\OAuth2JwtBearer\VerifiedAssertion;
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

/** @var array{assertion: string, publicKeyBase64: non-empty-string, signingKey: string, name: string, gate?: string, lockUser?: bool, expireAfterUsage?: bool, structuredError?: bool} $input */
$input = \json_decode($json, true, flags: \JSON_THROW_ON_ERROR);
$environment = new LeagueEnvironment(Postgres::connect($input['name']));
$publicKey = \base64_decode($input['publicKeyBase64'], true);

if (false === $publicKey || '' === $publicKey) {
    throw new RuntimeException('Invalid encoded public key.');
}

$environment->verificationKey = $publicKey;
$environment->signingKey = $input['signingKey'];
$resolvedIdentity = null;
$environment->resolveUser = static function (VerifiedAssertion $assertion) use (&$resolvedIdentity): string {
    $resolvedIdentity = ['userId' => 'internal-7', 'clientId' => $assertion->issuer->clientId];

    return 'internal-7';
};

if ($input['expireAfterUsage'] ?? false) {
    $environment->afterApplicationInsert = static function () use ($environment): void {
        $environment->clock->time = $environment->clock->time->modify('+63 seconds');
    };
}

if (isset($input['gate'])) {
    $environment->afterApplicationInsert = static function () use ($input): void {
        \touch($input['gate'] . '.ready');
        $deadline = \microtime(true) + 10;

        while (! \is_file($input['gate'] . '.release')) {
            if (\microtime(true) > $deadline) {
                throw new RuntimeException('Timed out waiting for the race coordinator.');
            }

            \usleep(10_000);
        }
    };
}

if ($input['lockUser'] ?? false) {
    $environment->resolveUser = static function (VerifiedAssertion $assertion) use ($environment, &$resolvedIdentity): string {
        $time = Postgres::value($environment->connection, 'SELECT current_time_value FROM locked_users WHERE id = 1 FOR UPDATE');

        if (! \is_string($time)) {
            throw new RuntimeException('Missing locked user time.');
        }

        $environment->clock->time = new DateTimeImmutable($time);
        $resolvedIdentity = ['userId' => 'internal-7', 'clientId' => $assertion->issuer->clientId];

        return 'internal-7';
    };
}

$request = new ServerRequest('POST', 'https://oauth.example/token')->withParsedBody([
    'grant_type' => \Noldors\OAuth2JwtBearer\JwtBearerGrant::IDENTIFIER,
    'assertion' => $input['assertion'],
]);

try {
    $environment->exchange($request);
    \fwrite(\STDOUT, 'success');
} catch (AssertionRejected|DomainException|OAuthServerException $exception) {
    if ($input['structuredError'] ?? false) {
        $previous = $exception instanceof AssertionRejected ? $exception : $exception->getPrevious();
        \fwrite(\STDOUT, \json_encode([
            'error' => $exception instanceof OAuthServerException ? $exception->getErrorType() : 'application_rejection',
            'reason' => $previous instanceof AssertionRejected ? $previous->reason->value : null,
            'identity' => $resolvedIdentity,
        ], \JSON_THROW_ON_ERROR));
    } else {
        \fwrite(\STDOUT, $exception instanceof OAuthServerException ? $exception->getErrorType() : 'application_rejection');
    }
}
