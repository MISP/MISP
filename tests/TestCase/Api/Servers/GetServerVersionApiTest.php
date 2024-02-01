<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Servers;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\ServersFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class GetServerVersionApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/servers/getVersion';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Servers',
    ];

    public function testGetServerVersion(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $response = $this->getJsonResponseAsArray();

        // read the version from the VERSION.json file
        $versionJson = json_decode(file_get_contents(ROOT . DS . 'VERSION.json'), true);
        $expectedVersion = $versionJson['major'] . '.' . $versionJson['minor'] . '.' . $versionJson['hotfix'];

        $this->assertEquals($expectedVersion, $response['version']);
    }
}
