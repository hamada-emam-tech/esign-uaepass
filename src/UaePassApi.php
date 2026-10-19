<?php

declare(strict_types=1);

namespace HamadaEmamTech\Esign\UaePass;

use HamadaEmamTech\Esign\Exceptions\ProviderError;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Talks to UAE PASS's signature service API: the client-credentials token (valid 10 minutes) and
 * the signer-process resources. Plain JSON, HTTP status codes mean what they say.
 *
 * Docs: https://docs.uaepass.ae/feature-guides/signature-integration-guide/digital-signature-single-document/signing-guide
 *
 * @internal used by UaePassProvider
 */
final class UaePassApi
{
    private const SCOPE = 'urn:safelayer:eidas:sign:process:document';

    private ?string $token = null;

    private int $tokenExpiresAt = 0;

    /** @var \Closure(): int */
    private readonly \Closure $clock;

    public function __construct(
        private readonly ClientInterface $http,
        private readonly RequestFactoryInterface $requests,
        private readonly StreamFactoryInterface $streams,
        private readonly UaePassCredentials $credentials,
        private readonly string $baseUrl,
        private readonly ?CacheInterface $cache = null,
        ?\Closure $clock = null,
    ) {
        $this->clock = $clock ?? static fn (): int => time();
    }

    /**
     * POST a multipart body.
     *
     * @param list<array{name: string, contents: string, filename?: string, type?: string}> $parts
     *
     * @return array{body: array<string, mixed>, headers: array<string, list<string>>}
     */
    public function postMultipart(string $path, array $parts): array
    {
        $boundary = '----esign' . bin2hex(random_bytes(12));
        $body = '';
        foreach ($parts as $part) {
            $body .= "--{$boundary}\r\nContent-Disposition: form-data; name=\"{$part['name']}\"";
            if (isset($part['filename'])) {
                $body .= '; filename="' . addcslashes($part['filename'], '"\\') . '"';
            }
            $body .= "\r\n";
            if (isset($part['type'])) {
                $body .= "Content-Type: {$part['type']}\r\n";
            }
            $body .= "\r\n{$part['contents']}\r\n";
        }
        $body .= "--{$boundary}--\r\n";

        $response = $this->call('POST', $path, $body, "multipart/form-data; boundary={$boundary}");

        return ['body' => $this->json($response, "POST {$path}"), 'headers' => $response->getHeaders()];
    }

    /** @return array<string, mixed> */
    public function getJson(string $path): array
    {
        return $this->json($this->call('GET', $path), "GET {$path}");
    }

    /** The raw body, e.g. a PDF. */
    public function getRaw(string $path): string
    {
        return (string) $this->call('GET', $path)->getBody();
    }

    public function delete(string $path): void
    {
        $this->call('DELETE', $path);
    }

    /**
     * Like getJson(), but a 404 returns null instead of throwing.
     *
     * @return array<string, mixed>|null
     */
    public function getJsonOrNull(string $path): ?array
    {
        try {
            return $this->getJson($path);
        } catch (ProviderError $e) {
            if ($e->httpStatus === 404) {
                return null;
            }
            throw $e;
        }
    }

    private function call(string $method, string $path, ?string $body = null, ?string $contentType = null, bool $isRetry = false): ResponseInterface
    {
        $request = $this->requests->createRequest($method, $this->baseUrl . $path)
            ->withHeader('Authorization', 'Bearer ' . $this->token())
            ->withHeader('Cache-Control', 'no-cache');
        if ($body !== null) {
            $request = $request->withHeader('Content-Type', (string) $contentType)->withBody($this->streams->createStream($body));
        }

        $response = $this->send($request, "{$method} {$path}");

        if ($response->getStatusCode() === 401 && ! $isRetry) {
            $this->forgetToken();

            return $this->call($method, $path, $body, $contentType, true);
        }
        if ($response->getStatusCode() >= 400) {
            throw $this->error($response, "{$method} {$path}");
        }

        return $response;
    }

    /** @return array<string, mixed> */
    private function json(ResponseInterface $response, string $what): array
    {
        $json = json_decode((string) $response->getBody(), true);

        return is_array($json) ? $json : throw new ProviderError('uaepass', "{$what} returned a non-JSON response.", $response->getStatusCode());
    }

    private function error(ResponseInterface $response, string $what): ProviderError
    {
        // UAE PASS doesn't document its error body. Use the usual OAuth/REST fields when present.
        $json = json_decode((string) $response->getBody(), true);
        $code = is_array($json) && is_string($json['error'] ?? null) ? $json['error'] : null;
        $detail = is_array($json) ? ($json['error_description'] ?? $json['message'] ?? null) : null;
        $message = is_string($detail) && $detail !== '' ? $detail : 'Request failed';

        return new ProviderError('uaepass', "{$what}: {$message}", $response->getStatusCode(), $code);
    }

    private function token(): string
    {
        $now = ($this->clock)();
        if ($this->token !== null && $now < $this->tokenExpiresAt) {
            return $this->token;
        }

        $cached = $this->cache?->get($this->cacheKey());
        if (is_array($cached) && is_string($cached['token'] ?? null) && (int) ($cached['expires_at'] ?? 0) > $now) {
            [$this->token, $this->tokenExpiresAt] = [$cached['token'], (int) $cached['expires_at']];

            return $this->token;
        }

        $request = $this->requests->createRequest('POST', $this->baseUrl . '/trustedx-authserver/oauth/main-as/token')
            ->withHeader('Authorization', 'Basic ' . base64_encode($this->credentials->clientId . ':' . $this->credentials->clientSecret))
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streams->createStream(http_build_query(['grant_type' => 'client_credentials', 'scope' => self::SCOPE])));

        $response = $this->send($request, 'token');
        if ($response->getStatusCode() >= 500) {
            throw new ProviderError('uaepass', 'UAE PASS authentication service is unavailable. Try again later.', $response->getStatusCode());
        }
        $json = json_decode((string) $response->getBody(), true);
        $token = is_array($json) ? ($json['access_token'] ?? null) : null;
        if ($response->getStatusCode() >= 400 || ! is_string($token) || $token === '') {
            $code = is_array($json) && is_string($json['error'] ?? null) ? $json['error'] : null;
            throw new ProviderError('uaepass', 'Authentication failed. Check client_id and client_secret.', $response->getStatusCode(), $code);
        }

        // Tokens last 600 seconds. Refresh one minute early.
        $lifetime = max(30, (int) ($json['expires_in'] ?? 600) - 60);
        $this->token = $token;
        $this->tokenExpiresAt = $now + $lifetime;
        $this->cache?->set($this->cacheKey(), ['token' => $token, 'expires_at' => $this->tokenExpiresAt], $lifetime);

        return $token;
    }

    private function forgetToken(): void
    {
        $this->token = null;
        $this->tokenExpiresAt = 0;
        $this->cache?->delete($this->cacheKey());
    }

    private function cacheKey(): string
    {
        return 'esign_uaepass_token_' . sha1($this->baseUrl . '|' . $this->credentials->clientId);
    }

    private function send(RequestInterface $request, string $what): ResponseInterface
    {
        try {
            return $this->http->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new ProviderError('uaepass', "{$what}: could not reach UAE PASS ({$e->getMessage()})", null, null, $e);
        }
    }
}
