# hamada-emam-tech/esign-uaepass

[UAE PASS](https://docs.uaepass.ae) digital signature driver for [hamada-emam-tech/esign](https://github.com/hamada-emam-tech/esign-php). The signer signs a PDF with their own UAE PASS identity: a qualified signature for verified (SOP3) accounts, advanced for SOP2. The output is PAdES.

> **Status:** built from UAE PASS's official documentation. Not yet verified against UAE PASS staging.

```bash
vendor/bin/esign add uaepass          # or: composer require hamada-emam-tech/esign-uaepass
```

## How UAE PASS differs from envelope platforms

| | UAE PASS |
|---|---|
| Who is invited | Nobody. `send()` returns a URL, and you redirect the signer's browser to it. |
| Before signing | The user must be logged in to your app **with UAE PASS** (UAE PASS requires this, so it can check that the same person signs). |
| Signers per envelope | 1. A second person signs the signed output in a new process, with a different `field_name` (`Sign2`). |
| Documents per envelope | 1 |
| Completion notice | No webhook. UAE PASS redirects the browser to your `finish_callback_url?status=…&signer_process_id=…`. It is unsigned, so treat it as a hint and call `status()`. |
| Identity method | `uae_pass` |

The core checks the signer count, document count and identity method from the declared capabilities before anything is sent.

## Configure

```php
$esign = new Esign([
    'default'   => 'uaepass',
    'providers' => [
        'uaepass' => [
            'environment'         => 'staging',               // or 'production'
            'client_id'           => getenv('UAEPASS_CLIENT_ID'),
            'client_secret'       => getenv('UAEPASS_CLIENT_SECRET'),
            'finish_callback_url' => 'https://app.example.ae/esign/uaepass/finished',
        ],
    ],
]);
```

| Option | Default | Notes |
|---|---|---|
| `environment` | `staging` | `staging` → `https://stg-id.uaepass.ae`, `production` → `https://id.uaepass.ae` |
| `client_id`, `client_secret` | required | Issued by UAE PASS during onboarding. Staging has public proof-of-concept credentials, listed in UAE PASS's docs. |
| `finish_callback_url` | none | Where the browser returns. `Envelope::$callbackUrl` overrides it per envelope. |
| `labels` | `[["digitalid","server","qualified"]]` | The signature level, as in UAE PASS's example. |
| `ui_locale` | `en_US` | |
| `skip_document_view` | `true` | `false` shows the document to the user before signing. |
| `field_name` | `Sign1` | Use a different name for every later signature on the same PDF. |
| `default_rectangle` | `{x:100, y:110, width:400, height:150}` | Used on the last page when the signer has no `SignatureField`. |
| `show_signature_details` | `true` | `false` hides the signer name and date from the visible signature. |
| `base_url`, `http_client`, `request_factory`, `stream_factory`, `cache` | | As for every driver. |

## Use it

```php
use HamadaEmamTech\Esign\Envelope\{Envelope, Document, Signer, SignatureField, IdentityMethod};

// The user is logged in with UAE PASS already.
$sent = $esign->send(new Envelope(
    documents: [Document::fromPath('contract.pdf')],
    signers:   [new Signer('Mariam', 'mariam@example.ae', IdentityMethod::UaePass, fields: [new SignatureField(page: 1, x: 100, y: 110, width: 400, height: 150)])],
));
$contract->esign_ref = (string) $sent->ref();          // "uaepass:sp_….dc_…" — keep the full ID
return redirect($sent->signingUrls['mariam@example.ae']);

// GET /esign/uaepass/finished?status=finished&signer_process_id=sp_…
$result = $esign->handleWebhook([], $_SERVER['QUERY_STRING'], 'uaepass');
if ($result->isValid() && $esign->status($contract->esign_ref) === EnvelopeStatus::Signed) {
    $pdf = $esign->download($contract->esign_ref);      // needs the full stored ID
    $esign->cancel($contract->esign_ref);               // clean up the process, as UAE PASS recommends
}
```

## Status mapping

| UAE PASS result | `EnvelopeStatus` |
|---|---|
| no result yet (404) | `Sent` |
| `finished` | `Signed` |
| `canceled` | `Cancelled` |
| `failed`, `failed_documents` | `Failed` |
| anything else | throws `ProviderError` |

`download()` runs only when the status is `Signed`, and only returns a PDF that carries a digital signature.

## Capabilities

| | UAE PASS |
|---|---|
| Identity methods | `uae_pass` |
| Documents / signers per envelope | 1 / 1 |
| Field placement, signing link | yes |
| Signing order, reminders, deadlines, signer details, webhook management | no |

## Open points to confirm on staging

1. **Result endpoint.** UAE PASS's endpoints table gives `/trustedx-resources/esignsp/v2/signer_processes/{id}/result`; its step-3 page shows `/trustedx-resources/esigp/v1/signatures/{id}/result`. The driver uses the endpoints table.
2. **Before the user finishes.** What the result endpoint returns is undocumented. The driver treats a 404 or a missing status as `Sent`.
3. **Coordinates.** The `rectangle` units and origin are undocumented. The driver passes `SignatureField` values through, rounded.
4. **Cancel.** `DELETE` on the process is documented as clean-up after download. The driver also uses it to cancel an unfinished process.

## Sources

- Signing guide: https://docs.uaepass.ae/feature-guides/signature-integration-guide/digital-signature-single-document/signing-guide
- Endpoints: …/signing-guide/endpoints
- Steps 1–6 (token, create, sign, obtain, delete): …/signing-guide/untitled/
- Onboarding: https://docs.uaepass.ae/getting-onboarded-with-uae-pass/onboarding-process-for-uae-pass-service-providers/initiation-phase
