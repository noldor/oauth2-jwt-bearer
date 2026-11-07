<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Lcobucci\JWT\Signer\Key\InMemory;
use Noldors\OAuth2JwtBearer\Algorithm;
use Noldors\OAuth2JwtBearer\TrustedIssuer;
use Noldors\OAuth2JwtBearer\VerificationKey;
use Noldors\OAuth2JwtBearer\AssertionRejected;
use Noldors\OAuth2JwtBearer\AssertionVerifier;
use PHPUnit\Framework\Attributes\DataProvider;
use Noldors\OAuth2JwtBearer\AssertionRequirements;
use Noldors\OAuth2JwtBearer\Contracts\KeyResolver;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\JwtFactory;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\MutableClock;

final class AssertionVerifierTest extends TestCase
{
    private MutableClock $clock;

    private AssertionVerifier $verifier;

    private KeyResolver $keys;

    protected function setUp(): void
    {
        $this->clock = new MutableClock();
        $this->keys = new class () implements KeyResolver {
            public function resolve(string $issuer, string $keyId): VerificationKey|null
            {
                return 'crm' === $issuer && \in_array($keyId, ['current', 'previous'], true)
                    ? new VerificationKey(Algorithm::RS256, InMemory::plainText(JwtFactory::keys()['public']))
                    : null;
            }
        };
        $this->verifier = new AssertionVerifier($this->keys, $this->clock, [
            new TrustedIssuer('crm', 'oauth-client', 'mail', new AssertionRequirements(60, 3, ['iat', 'jti']), allowedAlgorithms: [
                Algorithm::RS256,
            ]),
        ]);
    }

    public function testVerifiesExternalIdentityAndRotatedKey(): void
    {
        $verified = $this->verifier->verify(
            JwtFactory::assertion($this->claims(), ['kid' => 'previous']),
        );
        $this->assertSame('external-42', $verified->subject);
        $this->assertSame('oauth-client', $verified->issuer->clientId);
        $this->assertSame('once', $verified->id);
        $this->assertSame('crm', $verified->issuer->issuer);
    }

    /**
     * @param array<string, mixed> $changes
     */
    #[DataProvider('invalidClaims')]
    public function testRejectsInvalidClaims(array $changes): void
    {
        $this->expectException(AssertionRejected::class);
        $this->verifier->verify(
            JwtFactory::assertion(
                \array_replace($this->claims(), $changes),
            ),
        );
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function invalidClaims(): iterable
    {
        $now = 1_794_052_800;

        yield 'issuer not trusted' => [['iss' => 'attacker']];

        yield 'subject missing' => [['sub' => null]];

        yield 'subject numeric' => [['sub' => 42]];

        yield 'audience wrong' => [['aud' => 'other']];

        yield 'audience object' => [['aud' => ['unexpected' => 'mail']]];

        yield 'audience empty' => [['aud' => []]];

        yield 'numeric-string iat' => [['iat' => (string) $now]];

        yield 'numeric-string exp' => [['exp' => (string) ($now + 60)]];

        yield 'audience wrong type' => [['aud' => 42]];

        yield 'expiration missing' => [['exp' => null]];

        yield 'expiration wrong type' => [['exp' => 'tomorrow']];

        yield 'iat required' => [['iat' => null]];

        yield 'jti required' => [['jti' => null]];

        yield 'jti empty' => [['jti' => '']];

        yield 'expiration boundary' => [['iat' => $now - 60, 'exp' => $now - 3]];

        yield 'future iat' => [['iat' => $now + 4]];

        yield 'future nbf' => [['nbf' => $now + 4]];

        yield 'nbf wrong type' => [['nbf' => 'later']];

        yield 'lifetime too long' => [['exp' => $now + 61]];

        yield 'zero lifetime' => [['exp' => $now]];

        yield 'negative lifetime' => [['exp' => $now - 1]];
    }

    public function testAcceptsLeewayAndAudienceArray(): void
    {
        $claims = \array_replace($this->claims(), [
            'iat' => $this->clock->now()->getTimestamp() + 3,
            'nbf' => $this->clock->now()->getTimestamp() + 3,
            'aud' => ['other', 'mail'],
        ]);
        $this->assertSame('once', $this->verifier->verify(JwtFactory::assertion($claims))->id);
        $claims = \array_replace($this->claims(), [
            'iat' => $this->clock->now()->getTimestamp() - 60,
            'exp' => $this->clock->now()->getTimestamp() - 2,
        ]);
        $this->assertSame('once', $this->verifier->verify(JwtFactory::assertion($claims))->id);
    }

    /**
     * @param array<string, mixed> $headers
     */
    #[DataProvider('invalidHeaders')]
    public function testRejectsUntrustedHeaders(array $headers): void
    {
        $this->expectException(AssertionRejected::class);
        $this->verifier->verify(
            JwtFactory::assertion($this->claims(), $headers),
        );
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function invalidHeaders(): iterable
    {
        yield 'none' => [['alg' => 'none']];

        yield 'hmac confusion' => [['alg' => 'HS256']];

        yield 'different rsa' => [['alg' => 'RS384']];

        yield 'missing kid' => [['kid' => null]];

        yield 'unknown kid' => [['kid' => 'untrusted']];

        yield 'numeric kid' => [['kid' => 42]];

        yield 'critical extension' => [['crit' => ['custom'], 'custom' => true]];
    }

    public function testRejectsWrongSignature(): void
    {
        $this->expectException(AssertionRejected::class);
        $this->verifier->verify(
            JwtFactory::assertion($this->claims(), key: 'attacker'),
        );
    }

    public function testAllowsOptionalIssuedAtAndJtiWithoutReplay(): void
    {
        $verifier = $this->verifierFor(new AssertionRequirements(60, 3, []));
        $claims = $this->claims();
        unset($claims['iat'], $claims['jti']);
        $this->assertNull(
            $verifier->verify(JwtFactory::assertion($claims))->id,
        );
    }

    public function testExpirationRemainsMandatoryWithNoAdditionalRequiredClaims(): void
    {
        $verifier = $this->verifierFor(new AssertionRequirements(60, 3, []));
        $claims = $this->claims();
        unset($claims['exp']);
        $this->expectException(AssertionRejected::class);
        $verifier->verify(JwtFactory::assertion($claims));
    }

    public function testAdditionalLibraryConstraintsEnforceClaimValues(): void
    {
        $requirements = new AssertionRequirements(constraints: [
            new \Lcobucci\JWT\Validation\Constraint\HasClaimWithValue('purpose', 'mail-login'),
        ]);
        $verifier = $this->verifierFor($requirements);
        $this->assertSame('once', $verifier->verify(JwtFactory::assertion([
            ...$this->claims(),
            'purpose' => 'mail-login',
        ]))->id);
        $this->expectException(AssertionRejected::class);
        $verifier->verify(
            JwtFactory::assertion([...$this->claims(), 'purpose' => 'other']),
        );
    }

    public function testRechecksTimeAfterWaiting(): void
    {
        $verified = $this->verifier->verify(JwtFactory::assertion($this->claims()));
        $this->clock->time = $this->clock->time->modify('+63 seconds');
        $this->expectException(AssertionRejected::class);
        $this->verifier->assertValidAt($verified);
    }

    public function testVendorClaimDiagnosticIsNotRetainedInRejection(): void
    {
        $constraint = new class () implements \Lcobucci\JWT\Validation\Constraint {
            public function assert(\Lcobucci\JWT\Token $token): void
            {
                throw \Lcobucci\JWT\Validation\ConstraintViolation::error('Sensitive claim diagnostic.', $this);
            }
        };
        $verifier = $this->verifierFor(
            new AssertionRequirements(constraints: [$constraint]),
        );

        try {
            $verifier->verify(JwtFactory::assertion($this->claims()));
            $this->fail(
                'The claim constraint must reject the assertion.',
            );
        } catch (AssertionRejected $exception) {
            $this->assertSame(\Noldors\OAuth2JwtBearer\AssertionRejectionReason::CLAIMS_INVALID, $exception->reason);
            $this->assertNull($exception->getPrevious());
            $this->assertStringNotContainsString('Sensitive claim diagnostic.', $exception->getMessage());
        }
    }

    private function verifierFor(AssertionRequirements $requirements): AssertionVerifier
    {
        return new AssertionVerifier($this->keys, $this->clock, [
            new TrustedIssuer('crm', 'oauth-client', 'mail', $requirements, allowedAlgorithms: [Algorithm::RS256]),
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function claims(): array
    {
        return [
            'iss' => 'crm',
            'sub' => 'external-42',
            'aud' => 'mail',
            'iat' => $this->clock->now()->getTimestamp(),
            'exp' => $this->clock->now()->getTimestamp() + 60,
            'jti' => 'once',
        ];
    }
}
