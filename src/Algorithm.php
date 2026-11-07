<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Eddsa;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Rsa\Sha384;
use Lcobucci\JWT\Signer\Rsa\Sha512;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as Es256;

enum Algorithm: string
{
    case RS256 = 'RS256';
    case RS384 = 'RS384';
    case RS512 = 'RS512';
    case ES256 = 'ES256';
    case ES384 = 'ES384';
    case ES512 = 'ES512';
    case ED25519 = 'Ed25519';
    case EDDSA = 'EdDSA';

    public function signer(): Signer
    {
        return match ($this) {
            self::RS256 => new Sha256(),
            self::RS384 => new Sha384(),
            self::RS512 => new Sha512(),
            self::ES256 => new Es256(),
            self::ES384 => new \Lcobucci\JWT\Signer\Ecdsa\Sha384(),
            self::ES512 => new \Lcobucci\JWT\Signer\Ecdsa\Sha512(),
            self::ED25519 => new Signers\Ed25519(),
            self::EDDSA => new Eddsa(),
        };
    }
}
