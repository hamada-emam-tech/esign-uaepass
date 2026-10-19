<?php

declare(strict_types=1);

namespace HamadaEmamTech\Esign\UaePass;

/** How the signature is requested. The defaults are the values in UAE PASS's documentation. */
final readonly class UaePassOptions
{
    /**
     * @param list<list<string>>                       $labels       the signature level, e.g. [["digitalid","server","qualified"]]
     * @param array{x: int, y: int, width: int, height: int} $defaultRectangle where the signature goes when the signer has no SignatureField
     */
    public function __construct(
        /** Where UAE PASS sends the user's browser when signing ends. Envelope::$callbackUrl overrides it. */
        public ?string $finishCallbackUrl = null,
        public array $labels = [['digitalid', 'server', 'qualified']],
        public string $uiLocale = 'en_US',
        /** false shows the document to the user before signing. */
        public bool $skipDocumentView = true,
        public string $fieldName = 'Sign1',
        public array $defaultRectangle = ['x' => 100, 'y' => 110, 'width' => 400, 'height' => 150],
        public bool $showSignatureDetails = true,
    ) {
    }
}
