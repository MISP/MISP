<?php

declare(strict_types=1);

namespace App\Test\Helper;

use \WireMock\Client\WireMock;
use \WireMock\Client\ValueMatchingStrategy;
use \WireMock\Client\RequestPatternBuilder;
use \WireMock\Stubbing\StubMapping;

trait WireMockTestTrait
{
    /** @var WireMock */
    private $wiremock;

    /** @var array<mixed> */
    private $config = [
        'hostname' => 'localhost',
        'port' => 8080
    ];

    public function initializeWireMock(): void
    {
        $this->wiremock = WireMock::create(
            $_ENV['WIREMOCK_HOST'] ?? $this->config['hostname'],
            $_ENV['WIREMOCK_PORT'] ?? $this->config['port']
        );

        if (!$this->wiremock->isAlive()) {
            throw new \Exception('Failed to connect to WireMock server.');
        }

        $this->clearWireMockStubs();
    }

    public function clearWireMockStubs(): void
    {
        $this->wiremock->resetToDefault();
    }

    public function getWireMock(): WireMock
    {
        return $this->wiremock;
    }

    public function getWireMockBaseUrl(): string
    {
        return sprintf('http://%s:%s', $this->config['hostname'], $this->config['port']);
    }

    /** 
     * Verify all WireMock stubs were called.
     * 
     * @return void
     */
    public function verifyAllStubsCalled(): void
    {
        $stubs = $this->wiremock->listAllStubMappings()->getMappings();
        foreach ((array)$stubs as $stub) {
            $this->verifyStubCalled($stub);
        }
    }

    /** 
     * Verify the WireMock stub was called.
     * 
     * @param StubMapping $stub
     * @return void
     */
    public function verifyStubCalled(StubMapping $stub): void
    {
        $validator = new RequestPatternBuilder($stub->getRequest()->getMethod(), $stub->getRequest()->getUrlMatchingStrategy());

        // validate headers
        $headers = $stub->getRequest()->getHeaders();
        if (is_array($headers)) {
            foreach ($headers as $header => $rule) {
                $validator = $validator->withHeader($header, $rule);
            }
        }

        // TODO: Add body matching
        // TODO: Add query matching
        // TODO: Add cookie matching

        $this->wiremock->verify($validator);
    }
}
