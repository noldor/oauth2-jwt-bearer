<?php

declare(strict_types = 1);

namespace Noldors\OAuth2JwtBearer;

use DateInterval;
use SensitiveParameter;
use InvalidArgumentException;
use League\OAuth2\Server\RequestEvent;
use Psr\Http\Message\ServerRequestInterface;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\RequestAccessTokenEvent;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;

final class JwtBearerGrant extends AbstractGrant
{
    public const string IDENTIFIER = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

    private VerifiedAssertion|null $preparedAssertion = null;

    private string|null $localUserIdentifier = null;

    public function __construct(
        private readonly AssertionVerifier $verifier,
    ) {}

    /**
     * Trusted host API. Create a fresh grant and register it only on a per-call server.
     */
    public static function forVerifiedAssertion(
        AssertionVerifier $verifier,
        VerifiedAssertion $assertion,
        string $localUserIdentifier,
    ): self {
        if ('' === $localUserIdentifier) {
            throw new InvalidArgumentException('The local user identifier must be nonempty.');
        }

        $grant = new self($verifier);
        $grant->preparedAssertion = $assertion;
        $grant->localUserIdentifier = $localUserIdentifier;

        return $grant;
    }

    public function getIdentifier(): string
    {
        return self::IDENTIFIER;
    }

    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTtl,
    ): ResponseTypeInterface {
        $assertion = $this->getRequestParameter('assertion', $request);

        if (null === $assertion) {
            throw OAuthServerException::invalidRequest('assertion');
        }

        $this->rejectClientAssertion($request);

        try {
            $verified = $this->resolveAssertion($assertion, $request);
            $client = $this->resolveClient($request, $verified->issuer);
            $requestedScope = \array_key_exists('scope', (array) $request->getParsedBody())
                ? $this->getRequestParameter('scope', $request)
                : $this->defaultScope;
            $scopes = $this->validateScopes($requestedScope ?? []);
            $userId = $this->localUserIdentifier ?? $verified->subject;

            $scopes = $this->scopeRepository->finalizeScopes(
                $scopes,
                self::IDENTIFIER,
                $client,
                $userId,
            );
            $this->verifier->assertValidAt($verified);

            $accessToken = $this->issueAccessToken(
                $accessTokenTtl,
                $client,
                $userId,
                $scopes,
            );
            $this->verifier->assertValidAt($verified);
        } catch (AssertionRejected $exception) {
            throw $this->invalidGrant($exception);
        }

        $responseType->setAccessToken($accessToken);
        $this->getEmitter()->emit(
            new RequestAccessTokenEvent(RequestEvent::ACCESS_TOKEN_ISSUED, $request, $accessToken),
        );

        return $responseType;
    }

    private function resolveAssertion(#[SensitiveParameter] string $assertion, ServerRequestInterface $request): VerifiedAssertion
    {
        if (null === $this->preparedAssertion) {
            return $this->verifier->verify($assertion);
        }

        $original = ((array) $request->getParsedBody())['assertion'] ?? null;

        if (! \is_string($original) || ! \hash_equals($this->preparedAssertion->token->toString(), $original)) {
            throw new AssertionRejected('The prepared assertion does not match the request.', reason: AssertionRejectionReason::INVALID_ASSERTION);
        }

        $this->verifier->assertValidAt($this->preparedAssertion);

        return $this->preparedAssertion;
    }

    private function resolveClient(ServerRequestInterface $request, TrustedIssuer $issuer): ClientEntityInterface
    {
        $body = (array) $request->getParsedBody();
        $hasFormCredentials = \array_key_exists('client_id', $body) || \array_key_exists('client_secret', $body);
        $hasAuthorization = $request->hasHeader('Authorization');

        if (! $hasFormCredentials
            && ! $hasAuthorization
            && ClientAuthentication::OPTIONAL === $issuer->clientAuthentication
        ) {
            return $this->getClientEntityOrFail($issuer->clientId, $request);
        }

        if ($hasAuthorization) {
            [$basicClient] = $this->getBasicAuthCredentials($request);

            if (null === $basicClient || $hasFormCredentials || \count($request->getHeader('Authorization')) !== 1) {
                throw OAuthServerException::invalidClient($request);
            }
        }

        [$clientId, $secret] = $this->getClientCredentials($request);
        $client = $this->getClientEntityOrFail($clientId, $request);

        if ($clientId !== $issuer->clientId
            || '' === $secret
            || ! $this->clientRepository->validateClient($clientId, $secret, self::IDENTIFIER)
        ) {
            throw OAuthServerException::invalidClient($request);
        }

        return $client;
    }

    private function rejectClientAssertion(ServerRequestInterface $request): void
    {
        $body = (array) $request->getParsedBody();

        if (\array_key_exists('client_assertion', $body) || \array_key_exists('client_assertion_type', $body)) {
            throw OAuthServerException::invalidRequest(
                'client_assertion',
                'JWT client authentication is not supported by this grant.',
            );
        }
    }

    private function invalidGrant(AssertionRejected $rejection): OAuthServerException
    {
        $error = OAuthServerException::invalidGrant('The JWT assertion is invalid.');

        return new OAuthServerException(
            $error->getMessage(),
            $error->getCode(),
            $error->getErrorType(),
            $error->getHttpStatusCode(),
            $error->getHint(),
            previous: $rejection,
        );
    }
}
