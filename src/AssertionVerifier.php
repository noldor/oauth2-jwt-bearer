<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer;

use stdClass;
use DateInterval;
use DateTimeImmutable;
use SensitiveParameter;
use InvalidArgumentException;
use Psr\Clock\ClockInterface;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Validation\Validator;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Noldors\OAuth2JwtBearer\Contracts\KeyResolver;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;

final class AssertionVerifier
{
    /**
     * @var array<string, TrustedIssuer>
     */
    private readonly array $issuers;

    /**
     * @param non-empty-list<TrustedIssuer> $issuers
     */
    public function __construct(
        private readonly KeyResolver $keys,
        private readonly ClockInterface $clock,
        array $issuers,
    ) {
        $profiles = [];

        foreach ($issuers as $issuer) {
            if (isset($profiles[$issuer->issuer])) {
                throw new InvalidArgumentException('Duplicate trusted issuer.');
            }

            $profiles[$issuer->issuer] = $issuer;
        }

        $this->issuers = $profiles;
    }

    public function verify(#[SensitiveParameter] string $assertion): VerifiedAssertion
    {
        $token = $this->parse($assertion);
        $issuerName = $token->claims()->get('iss');
        $issuer = \is_string($issuerName) ? ($this->issuers[$issuerName] ?? null) : null;

        if (null === $issuer) {
            throw new AssertionRejected('Untrusted issuer.');
        }

        $this->verifySignature($token, $issuer);
        $this->validateClaims($token, $issuer);

        $subject = $token->claims()->get('sub');
        $expiresAt = $token->claims()->get('exp');
        $id = $token->claims()->get('jti');

        if (! \is_string($subject) || '' === $subject || ! $expiresAt instanceof DateTimeImmutable) {
            throw new AssertionRejected('Subject and expiration are required.');
        }

        if (null !== $id && (! \is_string($id) || '' === $id)) {
            throw new AssertionRejected('Invalid assertion ID.');
        }

        $verified = new VerifiedAssertion($issuer, $subject, $id, $expiresAt, $token);
        $this->assertValidAt($verified);

        return $verified;
    }

    /**
     * Revalidate with fresh time after application locks or replay contention.
     */
    public function assertValidAt(VerifiedAssertion $assertion): void
    {
        $requirements = $assertion->issuer->requirements;
        $leeway = new DateInterval('PT' . $requirements->leewaySeconds . 'S');

        try {
            new LooseValidAt($this->clock, $leeway)->assert($assertion->token);
        } catch (ConstraintViolation $exception) {
            throw new AssertionRejected('Assertion is outside its valid time window.', previous: $exception);
        }

        $issuedAt = $assertion->token->claims()->get('iat');
        $start = $issuedAt instanceof DateTimeImmutable ? $issuedAt : $this->clock->now();
        $maximumExpiry = $start->add(
            new DateInterval('PT' . $requirements->maxLifetimeSeconds . 'S'),
        );

        if (($issuedAt instanceof DateTimeImmutable && $assertion->expiresAt <= $start)
            || $assertion->expiresAt > $maximumExpiry
        ) {
            throw new AssertionRejected('Invalid assertion lifetime.');
        }
    }

    private function parse(string $assertion): UnencryptedToken
    {
        if ('' === $assertion) {
            throw new AssertionRejected('Empty JWT assertion.');
        }

        try {
            $token = new Parser(new JoseEncoder())->parse($assertion);
        } catch (CannotDecodeContent|InvalidTokenStructure|UnsupportedHeaderFound $exception) {
            throw new AssertionRejected('Malformed JWT assertion.', previous: $exception);
        }

        if (! $token instanceof UnencryptedToken) {
            throw new AssertionRejected('Only signed plaintext assertions are supported.');
        }

        return $token;
    }

    private function verifySignature(UnencryptedToken $token, TrustedIssuer $issuer): void
    {
        $algorithmName = $token->headers()->get('alg');
        $algorithm = \is_string($algorithmName) ? Algorithm::tryFrom($algorithmName) : null;
        $keyId = $token->headers()->get('kid');

        if (null === $algorithm || ! \in_array($algorithm, $issuer->allowedAlgorithms, true)) {
            throw new AssertionRejected('Disallowed signing algorithm.');
        }

        if (! \is_string($keyId) || '' === $keyId || $token->headers()->has('crit')) {
            throw new AssertionRejected('Missing key ID or unsupported critical headers.');
        }

        $key = $this->keys->resolve($issuer->issuer, $keyId);

        if (null === $key || $key->algorithm !== $algorithm) {
            throw new AssertionRejected('Untrusted signing key.');
        }

        try {
            new SignedWith($algorithm->signer(), $key->key)->assert($token);
        } catch (ConstraintViolation $exception) {
            throw new AssertionRejected('Invalid assertion signature.', previous: $exception);
        }
    }

    private function validateClaims(UnencryptedToken $token, TrustedIssuer $issuer): void
    {
        foreach ($issuer->requirements->requiredClaims as $claim) {
            if (! $token->claims()->has($claim) || $token->claims()->get($claim) === null) {
                throw new AssertionRejected('Missing required claim.');
            }
        }

        $this->validateClaimTypes($token);

        try {
            new Validator()->assert(
                $token,
                new IssuedBy($issuer->issuer),
                new PermittedFor($issuer->audience),
                ...$issuer->requirements->constraints,
            );
        } catch (RequiredConstraintsViolated $exception) {
            throw new AssertionRejected('Assertion claims were rejected.', previous: $exception);
        }
    }

    private function validateClaimTypes(UnencryptedToken $token): void
    {
        // The library accepts numeric strings; RFC 7519 NumericDate requires a JSON number.
        $encoder = new JoseEncoder();
        $json = $encoder->base64UrlDecode($token->claims()->toString());

        if ('' === $json) {
            throw new AssertionRejected('Empty claims.');
        }

        $claims = \json_decode($json, flags: \JSON_THROW_ON_ERROR);

        if (! $claims instanceof stdClass) {
            throw new AssertionRejected('Claims must be a JSON object.');
        }

        foreach (['iat', 'exp', 'nbf'] as $claim) {
            if (\property_exists($claims, $claim) && ! \is_int($claims->{$claim}) && ! \is_float($claims->{$claim})) {
                throw new AssertionRejected('Temporal claims must be JSON numbers.');
            }
        }

        $audience = $claims->aud ?? null;

        if (\is_string($audience) && '' !== $audience) {
            return;
        }

        if (! \is_array($audience)
            || ! \array_is_list($audience)
            || [] === $audience
            || \array_filter($audience, static fn (mixed $value): bool => ! \is_string($value) || '' === $value) !== []
        ) {
            throw new AssertionRejected('Audience must be a string or a nonempty list of strings.');
        }
    }
}
