<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Unit;

use RuntimeException;
use InvalidArgumentException;
use Lcobucci\JWT\Signer\Eddsa;
use PHPUnit\Framework\TestCase;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Rsa\Sha384;
use Lcobucci\JWT\Signer\Rsa\Sha512;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Noldors\OAuth2JwtBearer\Algorithm;
use Noldors\OAuth2JwtBearer\TrustedIssuer;
use Noldors\OAuth2JwtBearer\VerificationKey;
use Noldors\OAuth2JwtBearer\AssertionRejected;
use Noldors\OAuth2JwtBearer\AssertionVerifier;
use PHPUnit\Framework\Attributes\DataProvider;
use Noldors\OAuth2JwtBearer\Contracts\KeyResolver;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as EcdsaSha256;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\JwtFactory;
use Noldors\OAuth2JwtBearer\Tests\Fixtures\MutableClock;

final class AlgorithmsTest extends TestCase
{
    #[DataProvider('algorithms')]
    public function testVerifiesEachExplicitlyAllowedAlgorithm(string $name): void
    {
        [$assertion, $key] = $this->signedAssertion($name);
        $verifier = $this->verifier($key, [Algorithm::from($name)]);
        $this->assertSame('external-42', $verifier->verify($assertion)->subject);
    }

    #[DataProvider('algorithms')]
    public function testRejectsTamperedSignatureForEveryAlgorithm(string $name): void
    {
        [$assertion, $key] = $this->signedAssertion($name);
        $parts = \explode('.', $assertion);
        $signature = $parts[2];
        $parts[2] = ('A' === $signature[0] ? 'B' : 'A') . \mb_substr($signature, 1);
        $this->expectException(AssertionRejected::class);
        $this->verifier($key, [Algorithm::from($name)])->verify(\implode('.', $parts));
    }

    #[DataProvider('algorithms')]
    public function testRejectsAlgorithmOutsideIssuerAllowlist(string $name): void
    {
        [$assertion, $key] = $this->signedAssertion($name);
        $allowed = 'RS256' === $name ? Algorithm::ES256 : Algorithm::RS256;
        $this->expectException(AssertionRejected::class);
        $this->verifier($key, [$allowed])->verify($assertion);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function algorithms(): iterable
    {
        foreach (['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'EdDSA', 'Ed25519'] as $algorithm) {
            yield $algorithm => [$algorithm];
        }
    }

    public function testEd25519IsTheDefaultAlgorithm(): void
    {
        $profile = new TrustedIssuer('crm', 'oauth-client', 'mail');
        $this->assertSame([Algorithm::ED25519], $profile->allowedAlgorithms);
        [$assertion, $key] = $this->signedAssertion('Ed25519');
        $this->assertSame(
            'external-42',
            $this->verifier($key, $profile->allowedAlgorithms)->verify($assertion)->subject,
        );
    }

    public function testLegacyEdDsaIsNotAnAliasForEd25519(): void
    {
        [$assertion, $key] = $this->signedAssertion('EdDSA');
        $this->expectException(AssertionRejected::class);
        $this->verifier($key, [Algorithm::ED25519])->verify($assertion);
    }

    public function testEd25519IsNotAnAliasForLegacyEdDsa(): void
    {
        [$assertion, $key] = $this->signedAssertion('Ed25519');
        $this->expectException(AssertionRejected::class);
        $this->verifier($key, [Algorithm::EDDSA])->verify($assertion);
    }

    public function testInstalledNativeSignerDoesNotAcceptEd25519Identifier(): void
    {
        [$assertion, $key] = $this->signedAssertion('Ed25519');
        $token = \Noldors\OAuth2JwtBearer\Tests\Fixtures\OAuthResponse::token($assertion);
        $this->assertSame('EdDSA', new Eddsa()->algorithmId());
        $this->expectException(
            \Lcobucci\JWT\Validation\ConstraintViolation::class,
        );
        new \Lcobucci\JWT\Validation\Constraint\SignedWith(new Eddsa(), $key->key)->assert($token);
    }

    public function testKeyIsBoundToOneAlgorithmEvenWhenBothAreAllowed(): void
    {
        [$assertion] = $this->signedAssertion('RS384');
        $key = new VerificationKey(Algorithm::RS256, InMemory::plainText(JwtFactory::keys()['public']));
        $this->expectException(AssertionRejected::class);
        $this->verifier($key, [Algorithm::RS256, Algorithm::RS384])->verify($assertion);
    }

    public function testEs256RejectsDifferent256BitCurve(): void
    {
        $key = \openssl_pkey_new(['private_key_type' => \OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp256k1']);
        $this->assertNotFalse($key);
        $details = \openssl_pkey_get_details($key);
        $this->assertNotFalse($details);

        if (! \is_string($details['key']) || '' === $details['key']) {
            throw new RuntimeException('Cannot export test EC public key.');
        }

        $this->expectException(InvalidArgumentException::class);
        new VerificationKey(Algorithm::ES256, InMemory::plainText($details['key']));
    }

    /**
     * @return array{non-empty-string, VerificationKey}
     */
    private function signedAssertion(string $name): array
    {
        $keys = JwtFactory::keys();
        $private = $keys['private'];
        $public = $keys['public'];
        $signer = match ($name) {
            'RS256' => new Sha256(),
            'RS384' => new Sha384(),
            'RS512' => new Sha512(),
            'ES256' => new EcdsaSha256(),
            'ES384' => new \Lcobucci\JWT\Signer\Ecdsa\Sha384(),
            'ES512' => new \Lcobucci\JWT\Signer\Ecdsa\Sha512(),
            'EdDSA', 'Ed25519' => new Eddsa(),
            default => throw new InvalidArgumentException('Unknown test algorithm.'),
        };

        if (\in_array($name, ['ES256', 'ES384', 'ES512'], true)) {
            $curve = match ($name) {
                'ES256' => 'prime256v1', 'ES384' => 'secp384r1', 'ES512' => 'secp521r1',
            };
            $resource = \openssl_pkey_new(['private_key_type' => \OPENSSL_KEYTYPE_EC, 'curve_name' => $curve]);
            $this->assertNotFalse($resource);
            $private = '';
            \openssl_pkey_export($resource, $private);
            $details = \openssl_pkey_get_details($resource);
            $this->assertNotFalse($details);
            $public = $details['key'];
        }

        if (\in_array($name, ['EdDSA', 'Ed25519'], true)) {
            $pair = \sodium_crypto_sign_keypair();
            $private = \sodium_crypto_sign_secretkey($pair);
            $public = \sodium_crypto_sign_publickey($pair);
        }

        if (! \is_string($private) || '' === $private || ! \is_string($public) || '' === $public) {
            throw new RuntimeException('Cannot export test signing keys.');
        }

        $encoder = new JoseEncoder();
        $header = $encoder->base64UrlEncode(
            $encoder->jsonEncode(['alg' => $name, 'kid' => 'current']),
        );
        $claims = [
            'iss' => 'crm',
            'sub' => 'external-42',
            'aud' => 'mail',
            'iat' => 1_794_052_800,
            'exp' => 1_794_052_860,
            'jti' => 'once',
        ];
        $payload = $header . '.' . $encoder->base64UrlEncode($encoder->jsonEncode($claims));
        $assertion = $payload . '.' . $encoder->base64UrlEncode(
            $signer->sign($payload, InMemory::plainText($private)),
        );

        return [$assertion, new VerificationKey(Algorithm::from($name), InMemory::plainText($public))];
    }

    /**
     * @param non-empty-list<Algorithm> $allowed
     */
    private function verifier(VerificationKey $key, array $allowed): AssertionVerifier
    {
        $resolver = new class ($key) implements KeyResolver {
            public function __construct(
                private readonly VerificationKey $key,
            ) {}

            public function resolve(string $issuer, string $keyId): VerificationKey
            {
                return $this->key;
            }
        };

        return new AssertionVerifier($resolver, new MutableClock(), [
            new TrustedIssuer('crm', 'oauth-client', 'mail', allowedAlgorithms: $allowed),
        ]);
    }
}
