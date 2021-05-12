<?php

declare(strict_types=1);

namespace Helper\Module;

use Exception;
use \WireMock\Client\WireMock as WireMockClient;

final class WireMock extends \Codeception\Module
{

    /** @var array<mixed> */
    protected $config = [
        'hostname' => 'localhost',
        'port' => 8080,
    ];

    /** @var WireMockClient */
    private $wiremock;

    public function _initialize(): void
    {
        $this->wiremock = WireMockClient::create($this->config['hostname'], $this->config['port']);

        if (!$this->wiremock->isAlive()) {
            throw new Exception('Failed to connect to WireMock server.');
        }
    }

    public function getWireMock(): WireMockClient
    {
        return $this->wiremock;
    }
}
