<?php

declare(strict_types=1);

namespace HamadaEmamTech\Esign\UaePass\Tests\Support;

use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use HamadaEmamTech\Esign\UaePass\UaePassApi;
use HamadaEmamTech\Esign\UaePass\UaePassCredentials;
use HamadaEmamTech\Esign\UaePass\UaePassOptions;
use HamadaEmamTech\Esign\UaePass\UaePassProvider;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * An in-memory UAE PASS signature service, shaped like the requests and responses in its
 * documentation (docs.uaepass.ae, Digital Signature, single document).
 */
final class FakeUaePass implements ClientInterface
{
    public const SECRET = 'client-secret&#+';
    public const SIGNED = "%PDF-1.7 signed /ByteRange [0 10 20 30] /SubFilter /ETSI.CAdES.detached\n";

    /** @var list<array{method: string, path: string}> */
    public array $calls = [];

    /** @var array<string, mixed> the "process" part of the last create call */
    public array $lastProcess = [];

    public ?string $lastDocument = null;

    public int $tokenCalls = 0;

    public int $unauthorizedNext = 0;

    public bool $loginOutage = false;

    /** Return an unsigned file from /content, to test the signature check. */
    public bool $unsignedContent = false;

    /** @var array<string, array{documentId: string, result: ?string}> */
    private array $processes = [];

    private int $sequence = 0;

    public function provider(?UaePassOptions $options = null, ?\Closure $clock = null): UaePassProvider
    {
        $factory = new HttpFactory();

        return new UaePassProvider(
            new UaePassApi($this, $factory, $factory, new UaePassCredentials('sp-client', self::SECRET), 'https://stg-id.uaepass.test', null, $clock),
            $options ?? new UaePassOptions(finishCallbackUrl: 'https://app.example.ae/finished'),
        );
    }

    /** What UAE PASS reports once the user is done in the browser. */
    public function finish(string $processId, string $result = 'finished'): void
    {
        $this->processes[$processId]['result'] = $result;
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $path = $request->getUri()->getPath();

        if ($path === '/trustedx-authserver/oauth/main-as/token') {
            return $this->token($request);
        }

        $this->calls[] = ['method' => $request->getMethod(), 'path' => $path];
        if ($this->unauthorizedNext > 0) {
            --$this->unauthorizedNext;

            return new Response(401, [], '{"error":"invalid_token"}');
        }
        if ($request->getHeaderLine('Authorization') !== 'Bearer token-' . $this->tokenCalls) {
            return new Response(401, [], '{"error":"invalid_token"}');
        }

        return match (true) {
            $path === '/trustedx-resources/esignsp/v2/signer_processes' && $request->getMethod() === 'POST' => $this->create($request),
            (bool) preg_match('#^/trustedx-resources/esignsp/v2/signer_processes/(sp_\w+)/result$#', $path, $m) => $this->result($m[1]),
            (bool) preg_match('#^/trustedx-resources/esignsp/v2/documents/(dc_\w+)/content$#', $path, $m) => $this->content($m[1]),
            (bool) preg_match('#^/trustedx-resources/esignsp/v2/signer_processes/(sp_\w+)$#', $path, $m) && $request->getMethod() === 'DELETE' => $this->delete($m[1]),
            default => new Response(404),
        };
    }

    private function token(RequestInterface $request): ResponseInterface
    {
        if ($this->loginOutage) {
            return new Response(500);
        }
        parse_str((string) $request->getBody(), $form);
        $valid = $request->getHeaderLine('Authorization') === 'Basic ' . base64_encode('sp-client:' . self::SECRET)
            && ($form['grant_type'] ?? null) === 'client_credentials'
            && ($form['scope'] ?? null) === 'urn:safelayer:eidas:sign:process:document';
        if (! $valid) {
            return new Response(401, [], '{"error":"invalid_client"}');
        }
        ++$this->tokenCalls;

        return new Response(200, ['Content-Type' => 'application/json'], (string) json_encode([
            'access_token' => 'token-' . $this->tokenCalls, 'token_type' => 'Bearer', 'expires_in' => 600, 'scope' => 'urn:safelayer:eidas:sign:process:document',
        ]));
    }

    private function create(RequestInterface $request): ResponseInterface
    {
        preg_match('/boundary=(.+)$/', $request->getHeaderLine('Content-Type'), $m);
        $parts = [];
        foreach (explode('--' . ($m[1] ?? 'x'), (string) $request->getBody()) as $chunk) {
            if (preg_match('/name="([^"]+)".*?\r\n\r\n(.*)\r\n$/s', $chunk, $p) === 1) {
                $parts[$p[1]] = $p[2];
            }
        }
        if (! isset($parts['process'], $parts['document'])) {
            return new Response(400, [], '{"error":"invalid_request","error_description":"process and document parts are required"}');
        }
        $this->lastProcess = (array) json_decode($parts['process'], true);
        $this->lastDocument = $parts['document'];

        $n = ++$this->sequence;
        $processId = "sp_{$n}abc";
        $documentId = "dc_{$n}def";
        $this->processes[$processId] = ['documentId' => $documentId, 'result' => null];
        $base = 'https://stg-id.uaepass.test/trustedx-resources/esignsp/v2';

        return new Response(201, ['Location' => "{$base}/signer_processes/{$processId}", 'Content-Type' => 'application/json'], (string) json_encode([
            'id' => $processId,
            'self' => "{$base}/signer_processes/{$processId}",
            'process_type' => 'urn:safelayer:eidas:processes:document:sign:esigp',
            'tasks' => ['pending' => [['type' => 'UserBrowserTask', 'id' => "tk_{$n}", 'url' => "{$base}/ui?signerProcessId={$processId}"]]],
            'documents' => [['url' => "{$base}/documents/{$documentId}"]],
        ]));
    }

    private function result(string $processId): ResponseInterface
    {
        $result = $this->processes[$processId]['result'] ?? null;

        return $result === null
            ? new Response(404, [], '{"error":"not_found"}')
            : new Response(200, ['Content-Type' => 'application/json'], (string) json_encode(['status' => $result, 'details' => ['message' => '']]));
    }

    private function content(string $documentId): ResponseInterface
    {
        foreach ($this->processes as $process) {
            if ($process['documentId'] === $documentId) {
                return new Response(200, ['Content-Type' => 'application/pdf'], $this->unsignedContent ? "%PDF-1.7 original\n" : self::SIGNED);
            }
        }

        return new Response(404);
    }

    private function delete(string $processId): ResponseInterface
    {
        if (! isset($this->processes[$processId])) {
            return new Response(404);
        }
        $this->processes[$processId]['result'] = 'canceled';

        return new Response(204);
    }
}
