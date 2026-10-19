<?php

declare(strict_types=1);

namespace HamadaEmamTech\Esign\UaePass;

use HamadaEmamTech\Esign\Contracts\ProviderFactory;
use HamadaEmamTech\Esign\Contracts\SignatureProvider;
use HamadaEmamTech\Esign\Exceptions\EsignException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Builds the UAE PASS provider from its config block:
 *
 *     'uaepass' => [
 *         'environment'         => 'staging',              // or 'production'
 *         'client_id'           => '...', 'client_secret' => '...',
 *         'finish_callback_url' => 'https://app.example.ae/esign/uaepass/finished',
 *         // optional: labels, ui_locale, skip_document_view, field_name, default_rectangle,
 *         //           show_signature_details, base_url, http_client, request_factory,
 *         //           stream_factory, cache (PSR-16)
 *     ]
 */
final class UaePassFactory implements ProviderFactory
{
    public const BASE_URLS = [
        'staging' => 'https://stg-id.uaepass.ae',
        'production' => 'https://id.uaepass.ae',
    ];

    public function create(array $config): SignatureProvider
    {
        $missing = array_values(array_filter(['client_id', 'client_secret'], fn (string $key) => ! is_string($config[$key] ?? null) || $config[$key] === ''));
        if ($missing !== []) {
            throw new EsignException('UAE PASS config is missing: ' . implode(', ', $missing) . '.');
        }
        $environment = (string) ($config['environment'] ?? 'staging');
        $baseUrl = $config['base_url'] ?? self::BASE_URLS[$environment]
            ?? throw new EsignException("UAE PASS environment must be \"staging\" or \"production\", got \"{$environment}\".");

        $options = new UaePassOptions(
            finishCallbackUrl: is_string($config['finish_callback_url'] ?? null) ? $config['finish_callback_url'] : null,
            labels: $config['labels'] ?? [['digitalid', 'server', 'qualified']],
            uiLocale: (string) ($config['ui_locale'] ?? 'en_US'),
            skipDocumentView: (bool) ($config['skip_document_view'] ?? true),
            fieldName: (string) ($config['field_name'] ?? 'Sign1'),
            defaultRectangle: $config['default_rectangle'] ?? ['x' => 100, 'y' => 110, 'width' => 400, 'height' => 150],
            showSignatureDetails: (bool) ($config['show_signature_details'] ?? true),
        );

        [$client, $requests, $streams] = self::http($config);
        $cache = $config['cache'] ?? null;

        return new UaePassProvider(
            new UaePassApi($client, $requests, $streams, new UaePassCredentials((string) $config['client_id'], (string) $config['client_secret']), rtrim((string) $baseUrl, '/'), $cache instanceof CacheInterface ? $cache : null),
            $options,
        );
    }

    /**
     * The HTTP client you pass, or one that is installed: php-http/discovery, Guzzle 7, Symfony HttpClient.
     *
     * @param array<string, mixed> $config
     *
     * @return array{ClientInterface, RequestFactoryInterface, StreamFactoryInterface}
     */
    private static function http(array $config): array
    {
        $client = $config['http_client'] ?? null;
        $requests = $config['request_factory'] ?? null;
        $streams = $config['stream_factory'] ?? $requests;
        if ($client instanceof ClientInterface && $requests instanceof RequestFactoryInterface && $streams instanceof StreamFactoryInterface) {
            return [$client, $requests, $streams];
        }

        $discovery = 'Http\\Discovery\\Psr18ClientDiscovery';
        $factories = 'Http\\Discovery\\Psr17FactoryDiscovery';
        if (class_exists($discovery) && class_exists($factories)) {
            /** @var ClientInterface $found */
            $found = $discovery::find();
            /** @var RequestFactoryInterface $requestFactory */
            $requestFactory = $factories::findRequestFactory();
            /** @var StreamFactoryInterface $streamFactory */
            $streamFactory = $factories::findStreamFactory();

            return [$client instanceof ClientInterface ? $client : $found, $requests instanceof RequestFactoryInterface ? $requests : $requestFactory, $streams instanceof StreamFactoryInterface ? $streams : $streamFactory];
        }
        if (class_exists(\GuzzleHttp\Client::class) && class_exists(\GuzzleHttp\Psr7\HttpFactory::class)) {
            $factory = new \GuzzleHttp\Psr7\HttpFactory();

            return [$client instanceof ClientInterface ? $client : new \GuzzleHttp\Client(['timeout' => 60]), $factory, $factory];
        }
        $symfonyClass = 'Symfony\\Component\\HttpClient\\Psr18Client';
        if (class_exists($symfonyClass)) {
            /** @var ClientInterface&RequestFactoryInterface&StreamFactoryInterface $symfony */
            $symfony = new $symfonyClass();

            return [$client instanceof ClientInterface ? $client : $symfony, $symfony, $symfony];
        }

        throw new EsignException('UAE PASS needs a PSR-18 HTTP client. Run: composer require guzzlehttp/guzzle (or pass http_client, request_factory and stream_factory).');
    }
}
