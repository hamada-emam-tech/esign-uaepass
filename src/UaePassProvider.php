<?php

declare(strict_types=1);

namespace HamadaEmamTech\Esign\UaePass;

use HamadaEmamTech\Esign\Capabilities\Capabilities;
use HamadaEmamTech\Esign\Capabilities\Feature;
use HamadaEmamTech\Esign\Contracts\HasCapabilities;
use HamadaEmamTech\Esign\Contracts\Features\RecognizesWebhooks;
use HamadaEmamTech\Esign\Contracts\SignatureProvider;
use HamadaEmamTech\Esign\Support\Headers;
use HamadaEmamTech\Esign\Envelope\Envelope;
use HamadaEmamTech\Esign\Envelope\EnvelopeStatus;
use HamadaEmamTech\Esign\Envelope\IdentityMethod;
use HamadaEmamTech\Esign\Envelope\SentEnvelope;
use HamadaEmamTech\Esign\Envelope\WebhookEvent;
use HamadaEmamTech\Esign\Exceptions\EsignException;
use HamadaEmamTech\Esign\Exceptions\InvalidWebhook;
use HamadaEmamTech\Esign\Exceptions\ProviderError;

/**
 * UAE PASS digital signature: the signer signs a PDF with their own UAE PASS identity
 * (qualified for verified accounts), in their browser.
 *
 * How it differs from an envelope platform, all from UAE PASS's documentation:
 * - One signer and one document per signing process. A second signer signs the output of the first
 *   in a new process with another field name.
 * - Nobody is invited by email. send() returns a signing URL; redirect the user's browser to it.
 *   The user must already be logged in to your app with UAE PASS (required by UAE PASS).
 * - There is no webhook. When signing ends, UAE PASS redirects the browser to your
 *   finish_callback_url with ?status=…&signer_process_id=…. Pass that query string to
 *   parseWebhook()/handleWebhook(); it is unsigned, so the status always comes from status().
 *
 * The envelope ID is "<signer process id>.<document id>" (e.g. "sp_….dc_…"). Status and cancel use
 * the process ID; download needs the document ID. Store the full ID from $sent->ref().
 */
final class UaePassProvider implements SignatureProvider, HasCapabilities, RecognizesWebhooks
{
    private const PROCESS_TYPE = 'urn:safelayer:eidas:processes:document:sign:esigp';

    public function __construct(
        private readonly UaePassApi $api,
        private readonly UaePassOptions $options = new UaePassOptions(),
    ) {
    }

    public function name(): string
    {
        return 'uaepass';
    }

    public function capabilities(): Capabilities
    {
        return new Capabilities(
            identityMethods: [IdentityMethod::UaePass],
            features: [Feature::FieldPlacement, Feature::SigningUrls],
            maxDocuments: 1,
            maxSigners: 1,
        );
    }

    public function send(Envelope $envelope): SentEnvelope
    {
        if (count($envelope->documents) !== 1 || count($envelope->signers) !== 1) {
            throw new EsignException('UAE PASS signs one document by one signer per process. Run one process per signer.');
        }
        $document = $envelope->documents[0];
        $signer = $envelope->signers[0];
        if ($document->mimeType !== 'application/pdf') {
            throw new EsignException("UAE PASS signs PDFs only; \"{$document->name}\" is {$document->mimeType}.");
        }
        if ($signer->identity !== IdentityMethod::UaePass) {
            throw new EsignException("UAE PASS signers sign with their UAE PASS identity. Use IdentityMethod::UaePass for \"{$signer->name}\".");
        }
        if (count($signer->fields) > 1) {
            throw new EsignException('UAE PASS places one signature field per process.');
        }
        $callback = $envelope->callbackUrl ?? $this->options->finishCallbackUrl
            ?? throw new EsignException('UAE PASS needs a finish callback URL: set finish_callback_url, or Envelope::$callbackUrl.');

        $created = $this->api->postMultipart('/trustedx-resources/esignsp/v2/signer_processes', [
            ['name' => 'process', 'contents' => (string) json_encode($this->process($envelope, $callback), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), 'type' => 'application/json'],
            ['name' => 'document', 'contents' => $document->contents, 'filename' => $document->name, 'type' => 'application/pdf'],
        ])['body'];

        $processId = $created['id'] ?? null;
        $url = $created['tasks']['pending'][0]['url'] ?? null;
        $documentId = self::documentId($created['documents'][0]['url'] ?? null);
        if (! is_string($processId) || ! is_string($url) || $documentId === null) {
            throw new ProviderError('uaepass', 'The signer process was created without an id, a signing URL or a document URL.');
        }

        return new SentEnvelope('uaepass', "{$processId}.{$documentId}", EnvelopeStatus::Sent, [$signer->email => $url]);
    }

    public function status(string $envelopeId): EnvelopeStatus
    {
        [$processId] = self::split($envelopeId);
        // The endpoints table documents /signer_processes/{id}/result. Before the user finishes there
        // is no documented result yet, so a 404 or a missing status means the process is still open.
        $result = $this->api->getJsonOrNull('/trustedx-resources/esignsp/v2/signer_processes/' . rawurlencode($processId) . '/result');
        $status = is_array($result) ? ($result['status'] ?? null) : null;

        return match ($status) {
            null, '' => EnvelopeStatus::Sent,
            'finished' => EnvelopeStatus::Signed,
            'canceled', 'cancelled' => EnvelopeStatus::Cancelled,
            'failed', 'failed_documents' => EnvelopeStatus::Failed,
            default => throw new ProviderError('uaepass', 'UAE PASS returned a signing status this driver does not know: "' . (is_scalar($status) ? (string) $status : gettype($status)) . '". Please report it.'),
        };
    }

    public function download(string $envelopeId): string
    {
        [, $documentId] = self::split($envelopeId);
        if ($documentId === null) {
            throw new EsignException('download() needs the full UAE PASS envelope ID "sp_….dc_…" from $sent->ref(), not only the process ID.');
        }
        $status = $this->status($envelopeId);
        if ($status !== EnvelopeStatus::Signed) {
            throw new EsignException("UAE PASS process {$envelopeId} is {$status->value}, not signed. There is no signed PDF yet.");
        }

        $pdf = $this->api->getRaw('/trustedx-resources/esignsp/v2/documents/' . rawurlencode($documentId) . '/content');
        if (! str_starts_with($pdf, '%PDF') || ! str_contains($pdf, '/ByteRange')) {
            throw new ProviderError('uaepass', "UAE PASS returned no PDF with a digital signature for {$envelopeId}.");
        }

        return $pdf;
    }

    /** Deletes the signer process. UAE PASS documents this as clean-up; call it after download() too. */
    public function cancel(string $envelopeId): void
    {
        [$processId] = self::split($envelopeId);
        $this->api->delete('/trustedx-resources/esignsp/v2/signer_processes/' . rawurlencode($processId));
    }

    /** The browser redirect to finish_callback_url carries signer_process_id=sp_... in its query string. */
    public function recognizesWebhook(array $headers, string $rawBody): bool
    {
        return preg_match('/(^|[?&])signer_process_id=sp_[A-Za-z0-9]+/', $rawBody) === 1;
    }

    /**
     * UAE PASS has no webhook: pass the query string of the browser redirect to your
     * finish_callback_url (or the whole URL). It is unsigned and only says which process ended.
     */
    public function parseWebhook(array $headers, string $rawBody): WebhookEvent
    {
        $query = str_contains($rawBody, '?') ? (string) parse_url($rawBody, PHP_URL_QUERY) : $rawBody;
        parse_str(ltrim($query, '?'), $params);
        $processId = $params['signer_process_id'] ?? null;
        if (! is_string($processId) || preg_match('/^sp_[A-Za-z0-9]+$/', $processId) !== 1) {
            throw new InvalidWebhook('The UAE PASS redirect has no valid signer_process_id.');
        }

        // Only the process ID comes back. status() works with it; download() needs the stored full ID.
        $status = $params['status'] ?? null;

        return new WebhookEvent('uaepass', $processId, null, ['signer_process_id' => $processId, 'status' => is_string($status) ? $status : null]);
    }

    /** @return array<string, mixed> */
    private function process(Envelope $envelope, string $callback): array
    {
        $field = $envelope->signers[0]->fields[0] ?? null;
        $location = $field === null
            ? ['page' => ['number' => 'last'], 'rectangle' => $this->options->defaultRectangle]
            : ['page' => ['number' => (string) $field->page], 'rectangle' => [
                'x' => (int) round($field->x), 'y' => (int) round($field->y),
                'width' => (int) round($field->width), 'height' => (int) round($field->height),
            ]];

        return [
            'process_type' => self::PROCESS_TYPE,
            'labels' => $this->options->labels,
            'signer' => [
                'signature_policy_id' => 'urn:safelayer:eidas:policies:sign:document:pdf',
                'parameters' => [
                    'type' => 'pades-baseline',
                    'signature_field' => [
                        'name' => $this->options->fieldName,
                        'location' => $location,
                        'appearance' => $this->options->showSignatureDetails
                            ? ['signature_details' => ['details' => [['type' => 'subject', 'title' => 'Signer Name: '], ['type' => 'date', 'title' => 'Signature Date: ']]]]
                            : new \stdClass(),
                    ],
                ],
            ],
            'ui_locales' => [$this->options->uiLocale],
            'finish_callback_url' => $callback,
            'views' => ['document_agreement' => ['skip_server_id' => $this->options->skipDocumentView ? 'true' : 'false']],
            'timestamp' => ['provider_id' => 'urn:uae:tws:generation:policy:digitalid'],
        ];
    }

    private static function documentId(mixed $url): ?string
    {
        if (! is_string($url) || preg_match('#/documents/([A-Za-z0-9_]+)/?$#', $url, $m) !== 1) {
            return null;
        }

        return $m[1];
    }

    /** @return array{0: string, 1: ?string} the process ID and, when present, the document ID */
    private static function split(string $envelopeId): array
    {
        $parts = explode('.', $envelopeId, 2);

        return [$parts[0], isset($parts[1]) && $parts[1] !== '' ? $parts[1] : null];
    }
}
