<?php

declare(strict_types=1);

namespace Helper\Module;

use Codeception\TestInterface;
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

    public function _beforeSuite($settings = [])
    {
        $this->wiremock->resetToDefault();
    }

    public function _before(TestInterface $test)
    {
        $this->wiremock->resetToDefault();
    }

    public function getWireMock(): WireMockClient
    {
        return $this->wiremock;
    }

    public function mockGetServerVersionRequest(string $version = '2.4'): void
    {
        $this->wiremock->stubFor(
            WireMockClient::get(WireMockClient::urlEqualTo('/servers/getVersion'))
                ->willReturn(
                    WireMockClient::aResponse()
                        ->withHeader('Content-Type', 'application/json')
                        ->withBody(
                            (string)json_encode([
                                'version' => $version,
                                'perm_sync' => true,
                                'perm_sighting' => true,
                                'perm_galaxy_editor' => true,
                                'request_encoding' => [
                                    'gzip'
                                ]
                            ])
                        )
                )
        );
    }
}
