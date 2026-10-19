<?php

declare(strict_types=1);

namespace HamadaEmamTech\Esign\UaePass\Tests\Unit;

use HamadaEmamTech\Esign\Discovery\ProviderRegistry;
use HamadaEmamTech\Esign\Envelope\Document;
use HamadaEmamTech\Esign\Envelope\Envelope;
use HamadaEmamTech\Esign\Envelope\EnvelopeStatus;
use HamadaEmamTech\Esign\Envelope\IdentityMethod;
use HamadaEmamTech\Esign\Envelope\SignatureField;
use HamadaEmamTech\Esign\Envelope\Signer;
use HamadaEmamTech\Esign\Esign;
use HamadaEmamTech\Esign\Exceptions\EnvelopeNotSupported;
use HamadaEmamTech\Esign\Exceptions\EsignException;
use HamadaEmamTech\Esign\Exceptions\InvalidWebhook;
use HamadaEmamTech\Esign\Exceptions\ProviderError;
use HamadaEmamTech\Esign\UaePass\Tests\Support\FakeUaePass;
use HamadaEmamTech\Esign\UaePass\UaePassFactory;
use HamadaEmamTech\Esign\UaePass\UaePassOptions;
use HamadaEmamTech\Esign\Testing\AssertsProviderConformance;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class UaePassProviderTest extends TestCase
{
    use AssertsProviderConformance;

    private FakeUaePass $uaepass;

    protected function setUp(): void
    {
        $this->uaepass = new FakeUaePass();
    }

    /** @param list<SignatureField> $fields */
    private static function signer(array $fields = []): Signer
    {
        return new Signer('Mariam', 'mariam@example.ae', IdentityMethod::UaePass, fields: $fields);
    }

    private static function envelope(?Signer $signer = null, ?string $callback = null): Envelope
    {
        return new Envelope([new Document('contract.pdf', "%PDF-1.7 contract\n")], [$signer ?? self::signer()], callbackUrl: $callback);
    }

    #[Test]
    public function it_conforms_to_the_shared_provider_contract(): void
    {
        $this->assertProviderConformance(new UaePassFactory(), ['client_id' => 'a', 'client_secret' => 'b'], 'uaepass', __DIR__ . '/../../composer.json');
    }

    #[Test]
    public function send_creates_a_signer_process_and_returns_the_browser_url(): void
    {
        $sent = $this->uaepass->provider()->send(self::envelope(self::signer([new SignatureField(2, 50.4, 600, 200, 80)])));

        self::assertSame('sp_1abc.dc_1def', $sent->envelopeId);
        self::assertSame(['mariam@example.ae' => 'https://stg-id.uaepass.test/trustedx-resources/esignsp/v2/ui?signerProcessId=sp_1abc'], $sent->signingUrls);
        self::assertSame("%PDF-1.7 contract\n", $this->uaepass->lastDocument);

        $process = $this->uaepass->lastProcess;
        self::assertSame('urn:safelayer:eidas:processes:document:sign:esigp', $process['process_type']);
        self::assertSame([['digitalid', 'server', 'qualified']], $process['labels']);
        self::assertSame('pades-baseline', $process['signer']['parameters']['type']);
        self::assertSame('urn:safelayer:eidas:policies:sign:document:pdf', $process['signer']['signature_policy_id']);
        $field = $process['signer']['parameters']['signature_field'];
        self::assertSame('Sign1', $field['name']);
        self::assertSame(['number' => '2'], $field['location']['page']);
        self::assertSame(['x' => 50, 'y' => 600, 'width' => 200, 'height' => 80], $field['location']['rectangle']);
        self::assertSame('https://app.example.ae/finished', $process['finish_callback_url']);
        self::assertSame(['en_US'], $process['ui_locales']);
        self::assertSame('true', $process['views']['document_agreement']['skip_server_id']);
        self::assertSame('urn:uae:tws:generation:policy:digitalid', $process['timestamp']['provider_id']);
    }

    #[Test]
    public function without_a_field_the_signature_goes_on_the_last_page(): void
    {
        $this->uaepass->provider()->send(self::envelope());

        self::assertSame(['number' => 'last'], $this->uaepass->lastProcess['signer']['parameters']['signature_field']['location']['page']);
    }

    #[Test]
    public function the_envelope_callback_url_wins_over_the_configured_one(): void
    {
        $this->uaepass->provider()->send(self::envelope(callback: 'https://app.example.ae/contracts/42/signed'));

        self::assertSame('https://app.example.ae/contracts/42/signed', $this->uaepass->lastProcess['finish_callback_url']);
    }

    #[Test]
    public function what_uae_pass_cannot_do_is_refused_before_any_call(): void
    {
        $two = new Envelope([new Document('a.pdf', '%PDF a')], [self::signer(), new Signer('Omar', 'omar@example.ae', IdentityMethod::UaePass)]);
        $email = self::envelope(Signer::email('Omar', 'omar@example.ae'));
        $noCallback = $this->uaepass->provider(new UaePassOptions());

        foreach ([[$this->uaepass->provider(), $two, 'one signer'], [$this->uaepass->provider(), $email, 'IdentityMethod::UaePass'], [$noCallback, self::envelope(), 'finish callback URL']] as [$provider, $envelope, $message]) {
            try {
                $provider->send($envelope);
                self::fail("Expected: {$message}");
            } catch (EsignException $e) {
                self::assertStringContainsString($message, $e->getMessage());
            }
        }
        self::assertSame([], $this->uaepass->calls);
    }

    #[Test]
    public function the_core_refuses_a_second_signer_from_the_declared_capabilities(): void
    {
        $esign = (new Esign(['default' => 'uaepass', 'providers' => ['uaepass' => []]], new ProviderRegistry('/nonexistent')))
            ->extend('uaepass', fn () => $this->uaepass->provider());

        $this->expectException(EnvelopeNotSupported::class);
        $this->expectExceptionMessage('at most 1 signer(s)');
        $esign->send(new Envelope([new Document('a.pdf', '%PDF a')], [self::signer(), new Signer('Omar', 'omar@example.ae', IdentityMethod::UaePass)]));
    }

    #[Test]
    public function status_follows_the_documented_results(): void
    {
        $provider = $this->uaepass->provider();
        $id = $provider->send(self::envelope())->envelopeId;

        self::assertSame(EnvelopeStatus::Sent, $provider->status($id));   // no result yet
        foreach (['finished' => EnvelopeStatus::Signed, 'canceled' => EnvelopeStatus::Cancelled, 'failed' => EnvelopeStatus::Failed, 'failed_documents' => EnvelopeStatus::Failed] as $result => $expected) {
            $this->uaepass->finish('sp_1abc', $result);
            self::assertSame($expected, $provider->status($id), $result);
        }

        $this->uaepass->finish('sp_1abc', 'paused');
        $this->expectException(ProviderError::class);
        $this->expectExceptionMessage('"paused"');
        $provider->status($id);
    }

    #[Test]
    public function download_returns_the_signed_pdf_only_when_finished(): void
    {
        $provider = $this->uaepass->provider();
        $id = $provider->send(self::envelope())->envelopeId;

        try {
            $provider->download($id);
            self::fail('Download must refuse an unfinished process');
        } catch (EsignException $e) {
            self::assertStringContainsString('not signed', $e->getMessage());
        }

        $this->uaepass->finish('sp_1abc');
        self::assertSame(FakeUaePass::SIGNED, $provider->download($id));
    }

    #[Test]
    public function an_unsigned_file_is_never_returned_as_signed(): void
    {
        $provider = $this->uaepass->provider();
        $id = $provider->send(self::envelope())->envelopeId;
        $this->uaepass->finish('sp_1abc');
        $this->uaepass->unsignedContent = true;

        $this->expectException(ProviderError::class);
        $provider->download($id);
    }

    #[Test]
    public function download_needs_the_full_id_not_just_the_process_id(): void
    {
        $this->expectException(EsignException::class);
        $this->expectExceptionMessage('full UAE PASS envelope ID');
        $this->uaepass->provider()->download('sp_1abc');
    }

    #[Test]
    public function cancel_deletes_the_signer_process(): void
    {
        $provider = $this->uaepass->provider();
        $id = $provider->send(self::envelope())->envelopeId;
        $provider->cancel($id);

        self::assertSame(['method' => 'DELETE', 'path' => '/trustedx-resources/esignsp/v2/signer_processes/sp_1abc'], $this->uaepass->calls[1]);
        self::assertSame(EnvelopeStatus::Cancelled, $provider->status($id));
    }

    #[Test]
    public function the_browser_redirect_is_read_as_a_hint_and_status_works_with_its_id(): void
    {
        $provider = $this->uaepass->provider();
        $provider->send(self::envelope());
        $this->uaepass->finish('sp_1abc');

        foreach (['status=finished&signer_process_id=sp_1abc', '?status=finished&signer_process_id=sp_1abc', 'https://app.example.ae/finished?status=finished&signer_process_id=sp_1abc'] as $redirect) {
            $event = $provider->parseWebhook([], $redirect);
            self::assertSame('sp_1abc', $event->envelopeId);
            self::assertSame('finished', $event->payload['status']);
        }
        self::assertSame(EnvelopeStatus::Signed, $provider->status($event->envelopeId));
    }

    #[Test]
    public function a_redirect_without_a_valid_process_id_is_refused(): void
    {
        $this->expectException(InvalidWebhook::class);
        $this->uaepass->provider()->parseWebhook([], 'status=finished&signer_process_id=../../etc');
    }

    #[Test]
    public function the_token_is_reused_refreshed_and_retried_once_on_401(): void
    {
        $now = 1_000_000;
        $provider = $this->uaepass->provider(clock: function () use (&$now) {
            return $now;
        });
        $id = $provider->send(self::envelope())->envelopeId;
        $provider->status($id);
        self::assertSame(1, $this->uaepass->tokenCalls);

        $now += 600 - 59;          // inside the one-minute margin
        $provider->status($id);
        self::assertSame(2, $this->uaepass->tokenCalls);

        $this->uaepass->unauthorizedNext = 1;
        self::assertSame(EnvelopeStatus::Sent, $provider->status($id));
        self::assertSame(3, $this->uaepass->tokenCalls);
    }

    #[Test]
    public function failed_logins_and_outages_never_leak_the_secret(): void
    {
        $badSecret = new \HamadaEmamTech\Esign\UaePass\UaePassProvider(
            new \HamadaEmamTech\Esign\UaePass\UaePassApi($this->uaepass, new \GuzzleHttp\Psr7\HttpFactory(), new \GuzzleHttp\Psr7\HttpFactory(), new \HamadaEmamTech\Esign\UaePass\UaePassCredentials('sp-client', 'wrong-secret-value'), 'https://stg-id.uaepass.test'),
            new UaePassOptions(finishCallbackUrl: 'https://app.example.ae/finished'),
        );
        try {
            $badSecret->send(self::envelope());
            self::fail('Expected ProviderError');
        } catch (ProviderError $e) {
            self::assertSame('invalid_client', $e->providerCode);
            self::assertStringNotContainsString('wrong-secret-value', $e->getMessage());
        }

        $this->uaepass->loginOutage = true;
        try {
            $this->uaepass->provider()->send(self::envelope());
            self::fail('Expected ProviderError');
        } catch (ProviderError $e) {
            self::assertSame(500, $e->httpStatus);
            self::assertStringContainsString('unavailable', $e->getMessage());
        }
    }

    #[Test]
    public function the_factory_validates_its_config(): void
    {
        try {
            (new UaePassFactory())->create(['client_id' => '']);
            self::fail('Expected EsignException');
        } catch (EsignException $e) {
            self::assertStringContainsString('client_id, client_secret', $e->getMessage());
        }

        $this->expectException(EsignException::class);
        $this->expectExceptionMessage('"staging" or "production"');
        (new UaePassFactory())->create(['client_id' => 'a', 'client_secret' => 'b', 'environment' => 'qa']);
    }

    #[Test]
    public function credentials_stay_out_of_debug_output(): void
    {
        self::assertStringNotContainsString('very-secret', print_r(new \HamadaEmamTech\Esign\UaePass\UaePassCredentials('id', 'very-secret'), true));
    }
}
