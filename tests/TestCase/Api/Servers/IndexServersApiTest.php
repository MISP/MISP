<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Servers;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\ServersFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class IndexServersApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/servers/index';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Servers',
    ];

    public function testIndexServers(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $this->get(self::ENDPOINT);

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"name": "%s"', ServersFixture::SERVER_A_NAME));
        $this->assertResponseContains(sprintf('"name": "%s"', ServersFixture::SERVER_B_NAME));
        $this->assertResponseContains(sprintf('"name": "%s"', ServersFixture::SERVER_C_NAME));
    }
}
