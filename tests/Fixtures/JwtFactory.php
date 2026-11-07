<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer\Tests\Fixtures;

use RuntimeException;

final class JwtFactory
{
    /**
     * @var array<string, array{private: non-empty-string, public: non-empty-string}>
     */
    private static array $keys = [];

    /**
     * @return array{private: non-empty-string, public: non-empty-string}
     */
    public static function keys(string $name = 'crm'): array
    {
        if (\str_starts_with($name, 'ed25519:') && ! isset(self::$keys[$name])) {
            $pair = \sodium_crypto_sign_keypair();
            self::$keys[$name] = [
                'private' => \sodium_crypto_sign_secretkey($pair),
                'public' => \sodium_crypto_sign_publickey($pair),
            ];
        }

        if (! isset(self::$keys[$name])) {
            $key = \openssl_pkey_new(['private_key_bits' => 2_048, 'private_key_type' => \OPENSSL_KEYTYPE_RSA]);

            if (false === $key || ! \openssl_pkey_export($key, $private)) {
                throw new RuntimeException('Cannot create test RSA key.');
            }

            $details = \openssl_pkey_get_details($key);

            if (false === $details
                || ! \is_string($details['key'])
                || '' === $details['key']
                || ! \is_string($private)
                || '' === $private
            ) {
                throw new RuntimeException('Cannot export test RSA public key.');
            }

            self::$keys[$name] = ['private' => $private, 'public' => $details['key']];
        }

        return self::$keys[$name];
    }

    /** @param array<string, mixed> $claims
     * @param array<string, mixed> $headers
     */
    public static function assertion(array $claims, array $headers = [], string $key = 'crm'): string
    {
        $header = ['typ' => 'JWT', 'alg' => 'RS256', 'kid' => 'current', ...$headers];
        $payload = self::encode(
            \json_encode($header, \JSON_THROW_ON_ERROR),
        ) . '.' . self::encode(
            \json_encode($claims, \JSON_THROW_ON_ERROR),
        );

        if (\in_array($header['alg'], ['Ed25519', 'EdDSA'], true)) {
            $signature = new \Lcobucci\JWT\Signer\Eddsa()->sign(
                $payload,
                \Lcobucci\JWT\Signer\Key\InMemory::plainText(self::keys('ed25519:' . $key)['private']),
            );

            return $payload . '.' . self::encode($signature);
        }

        $signature = '';

        if (! \openssl_sign($payload, $signature, self::keys($key)['private'], \OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('Cannot sign test assertion.');
        }

        if (! \is_string($signature) || '' === $signature) {
            throw new RuntimeException('Empty test signature.');
        }

        return $payload . '.' . self::encode($signature);
    }

    private static function encode(string $value): string
    {
        return \mb_rtrim(\strtr(\base64_encode($value), '+/', '-_'), '=');
    }
}
