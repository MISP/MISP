<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Servers;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\ServersFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class DeleteServerApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/servers/delete';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Servers',
    ];

    public function testDeleteServer(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $url = sprintf('%s/%d', self::ENDPOINT, ServersFixture::SERVER_B_ID);

        $this->assertDbRecordExists('Servers', ['id' => ServersFixture::SERVER_B_ID]);

        $this->post($url);
        $this->assertResponseOk();
        $this->assertDbRecordNotExists('Servers', ['id' => ServersFixture::SERVER_B_ID]);
    }
}
