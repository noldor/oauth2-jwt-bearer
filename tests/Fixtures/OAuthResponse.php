<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Fixtures;

use PHPUnit\Framework\Assert;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Psr\Http\Message\ResponseInterface;

final class OAuthResponse
{
    /**
     * @return array{access_token: non-empty-string, expires_in: int, token_type: string}
     */
    public static function body(ResponseInterface $response): array
    {
        $body = \json_decode((string) $response->getBody(), true, flags: \JSON_THROW_ON_ERROR);
        Assert::assertIsArray($body);
        Assert::assertArrayHasKey('access_token', $body);
        Assert::assertArrayHasKey('expires_in', $body);
        Assert::assertArrayHasKey('token_type', $body);
        Assert::assertIsString($body['access_token']);
        Assert::assertNotSame('', $body['access_token']);
        Assert::assertIsInt($body['expires_in']);
        Assert::assertIsString($body['token_type']);

        /** @var array{access_token: non-empty-string, expires_in: int, token_type: string} $body */
        return $body;
    }

    /**
     * @param non-empty-string $value
     */
    public static function token(string $value): UnencryptedToken
    {
        $token = new Parser(new JoseEncoder())->parse($value);
        Assert::assertInstanceOf(UnencryptedToken::class, $token);

        return $token;
    }
}
