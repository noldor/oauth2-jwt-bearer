<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer;

use Lcobucci\JWT\Signer\Key;
use InvalidArgumentException;

final readonly class VerificationKey
{
    /**
     * Ed25519 uses raw 32-byte public keys; RSA and ES256 use PEM public keys.
     */
    public function __construct(
        public Algorithm $algorithm,
        public Key $key,
    ) {
        if (\in_array($algorithm, [Algorithm::ED25519, Algorithm::EDDSA], true)) {
            if (\mb_strlen($key->contents(), '8bit') !== \SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                throw new InvalidArgumentException('Ed25519 requires a raw 32-byte public key.');
            }

            return;
        }

        $public = \openssl_pkey_get_public($key->contents());
        $details = false === $public ? false : \openssl_pkey_get_details($public);

        if (false === $details) {
            throw new InvalidArgumentException('A valid PEM public key is required.');
        }

        $curve = match ($algorithm) {
            Algorithm::ES256 => 'prime256v1',
            Algorithm::ES384 => 'secp384r1',
            Algorithm::ES512 => 'secp521r1',
            default => null,
        };

        if (null !== $curve) {
            if (\OPENSSL_KEYTYPE_EC !== $details['type']
                || ! \is_array($details['ec'] ?? null)
                || $curve !== ($details['ec']['curve_name'] ?? null)
            ) {
                throw new InvalidArgumentException('The EC key must use the curve required by its algorithm.');
            }
        } elseif (\OPENSSL_KEYTYPE_RSA !== $details['type'] || 2_048 > $details['bits']) {
            throw new InvalidArgumentException('RSA requires an RSA public key of at least 2048 bits.');
        }
    }
}
