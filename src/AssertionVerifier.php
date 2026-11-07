<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer;

use stdClass;
use DateInterval;
use JsonException;
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
            throw new AssertionRejected('Untrusted issuer.', reason: AssertionRejectionReason::CLAIMS_INVALID);
        }

        $this->verifySignature($token, $issuer);
        $this->validateClaims($token, $issuer);

        $subject = $token->claims()->get('sub');
        $expiresAt = $token->claims()->get('exp');
        $id = $token->claims()->get('jti');

        if (! \is_string($subject) || '' === $subject || ! $expiresAt instanceof DateTimeImmutable) {
            throw new AssertionRejected('Subject and expiration are required.', reason: AssertionRejectionReason::CLAIMS_INVALID);
        }

        if (null !== $id && (! \is_string($id) || '' === $id)) {
            throw new AssertionRejected('Invalid assertion ID.', reason: AssertionRejectionReason::CLAIMS_INVALID);
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

        $now = $this->clock->now();

        if ($assertion->token->isExpired($now->sub($leeway))) {
            throw new AssertionRejected('The assertion has expired.', reason: AssertionRejectionReason::EXPIRED);
        }

        $latestAllowed = $now->add($leeway);

        if (! $assertion->token->hasBeenIssuedBefore($latestAllowed)
            || ! $assertion->token->isMinimumTimeBefore($latestAllowed)
        ) {
            throw new AssertionRejected('The assertion is not yet valid.', reason: AssertionRejectionReason::NOT_YET_VALID);
        }

        $issuedAt = $assertion->token->claims()->get('iat');
        $start = $issuedAt instanceof DateTimeImmutable ? $issuedAt : $now;
        $maximumExpiry = $start->add(
            new DateInterval('PT' . $requirements->maxLifetimeSeconds . 'S'),
        );

        if (($issuedAt instanceof DateTimeImmutable && $assertion->expiresAt <= $start)
            || $assertion->expiresAt > $maximumExpiry
        ) {
            throw new AssertionRejected('Invalid assertion lifetime.', reason: AssertionRejectionReason::CLAIMS_INVALID);
        }
    }

    private function parse(#[SensitiveParameter] string $assertion): UnencryptedToken
    {
        if ('' === $assertion) {
            throw new AssertionRejected('Empty JWT assertion.', reason: AssertionRejectionReason::INVALID_ASSERTION);
        }

        try {
            // Preserve raw claim types before the library normalizes dates/audience.
            // This is structural validation only; no identity is trusted here.
            $parts = \explode('.', $assertion);

            if (\count($parts) === 3 && '' !== $parts[1]) {
                $this->validateClaimTypes($parts[1]);
            }

            $token = new Parser(new JoseEncoder())->parse($assertion);
        } catch (CannotDecodeContent|InvalidTokenStructure|JsonException|UnsupportedHeaderFound) {
            throw new AssertionRejected('Malformed JWT assertion.', reason: AssertionRejectionReason::INVALID_ASSERTION);
        }

        if (! $token instanceof UnencryptedToken) {
            throw new AssertionRejected('Only signed plaintext assertions are supported.', reason: AssertionRejectionReason::INVALID_ASSERTION);
        }

        return $token;
    }

    private function verifySignature(UnencryptedToken $token, TrustedIssuer $issuer): void
    {
        $algorithmName = $token->headers()->get('alg');
        $algorithm = \is_string($algorithmName) ? Algorithm::tryFrom($algorithmName) : null;
        $keyId = $token->headers()->get('kid');

        if (null === $algorithm || ! \in_array($algorithm, $issuer->allowedAlgorithms, true)) {
            throw new AssertionRejected('Disallowed signing algorithm.', reason: AssertionRejectionReason::ALGORITHM_INVALID);
        }

        if ($token->headers()->has('crit')) {
            throw new AssertionRejected('Unsupported critical headers.', reason: AssertionRejectionReason::INVALID_ASSERTION);
        }

        if (! \is_string($keyId) || '' === $keyId) {
            throw new AssertionRejected('Missing signing key ID.', reason: AssertionRejectionReason::KEY_UNKNOWN);
        }

        $key = $this->keys->resolve($issuer->issuer, $keyId);

        if (null === $key) {
            throw new AssertionRejected('Untrusted signing key.', reason: AssertionRejectionReason::KEY_UNKNOWN);
        }

        if ($key->algorithm !== $algorithm) {
            throw new AssertionRejected('Signing key algorithm mismatch.', reason: AssertionRejectionReason::ALGORITHM_INVALID);
        }

        try {
            new SignedWith($algorithm->signer(), $key->key)->assert($token);
        } catch (ConstraintViolation) {
            throw new AssertionRejected('Invalid assertion signature.', reason: AssertionRejectionReason::SIGNATURE_INVALID);
        }
    }

    private function validateClaims(UnencryptedToken $token, TrustedIssuer $issuer): void
    {
        foreach ($issuer->requirements->requiredClaims as $claim) {
            if (! $token->claims()->has($claim) || $token->claims()->get($claim) === null) {
                throw new AssertionRejected('Missing required claim.', reason: AssertionRejectionReason::CLAIMS_INVALID);
            }
        }

        try {
            new Validator()->assert(
                $token,
                new IssuedBy($issuer->issuer),
                new PermittedFor($issuer->audience),
                ...$issuer->requirements->constraints,
            );
        } catch (RequiredConstraintsViolated) {
            throw new AssertionRejected('Assertion claims were rejected.', reason: AssertionRejectionReason::CLAIMS_INVALID);
        }
    }

    private function validateClaimTypes(#[SensitiveParameter] string $encodedClaims): void
    {
        // The library accepts numeric strings; RFC 7519 NumericDate requires a JSON number.
        $encoder = new JoseEncoder();
        $json = $encoder->base64UrlDecode($encodedClaims);

        if ('' === $json) {
            throw new AssertionRejected('Empty claims.', reason: AssertionRejectionReason::CLAIMS_INVALID);
        }

        $claims = \json_decode($json, flags: \JSON_THROW_ON_ERROR);

        if (! $claims instanceof stdClass) {
            throw new AssertionRejected('Claims must be a JSON object.', reason: AssertionRejectionReason::CLAIMS_INVALID);
        }

        foreach (['iat', 'exp', 'nbf'] as $claim) {
            if (\property_exists($claims, $claim) && ! \is_int($claims->{$claim}) && ! \is_float($claims->{$claim})) {
                throw new AssertionRejected('Temporal claims must be JSON numbers.', reason: AssertionRejectionReason::CLAIMS_INVALID);
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
            throw new AssertionRejected('Audience must be a string or a nonempty list of strings.', reason: AssertionRejectionReason::CLAIMS_INVALID);
        }
    }
}
