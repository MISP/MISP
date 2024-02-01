<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Servers;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\ServersFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;
use Cake\Http\TestSuite\HttpClientTrait;

class TestConnectionApiTest extends TestCase
{
    use ApiTestTrait;
    use HttpClientTrait;

    protected const ENDPOINT = '/servers/testConnection';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Servers',
    ];

    public function testTestConnection(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%s', self::ENDPOINT, ServersFixture::SERVER_A_ID);

        $headers = [
            'Content-Type: application/json',
            'Connection: close',
        ];

        $getVersionBody = json_encode(
            [
                "version" => "3.0.0",
                "pymisp_recommended_version" => "3.0.0",
                "perm_sync" => true,
                "perm_sighting" => true,
                "perm_galaxy_editor" => true,
                "request_encoding" => [
                    "gzip",
                    "br"
                ],
                "filter_sightings" => true
            ]
        );

        // mock the [remote]/servers/getVersion request
        $this->mockClientGet(
            ServersFixture::SERVER_A_URL . '/servers/getVersion',
            $this->newClientResponse(200, $headers, $getVersionBody)
        );

        $this->get($url);

        $this->assertResponseOk();
        $response = $this->getJsonResponseAsArray();

        $this->assertArrayHasKey('version', $response);
        $this->assertEquals('3.0.0', $response['version']);
    }
}
