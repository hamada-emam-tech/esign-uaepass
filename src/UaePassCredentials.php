<?php

declare(strict_types=1);

namespace HamadaEmamTech\Esign\UaePass;

/** The client credentials UAE PASS issues to a service provider. Kept out of var_dump() and error trackers. */
final readonly class UaePassCredentials
{
    public function __construct(
        public string $clientId,
        #[\SensitiveParameter] public string $clientSecret,
    ) {
    }

    /** @return array<string, string> */
    public function __debugInfo(): array
    {
        return ['clientId' => $this->clientId, 'clientSecret' => '***'];
    }
}
