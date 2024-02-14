<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Servers;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class AddServerApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/servers/add';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Servers'
    ];

    public function testAddServer(): void
    {
        $this->skipOpenApiValidations();

        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $faker = \Faker\Factory::create();

        $this->post(
            self::ENDPOINT,
            [
                "name" => "Test Server",
                "url" => $faker->url,
                "remote_org_id" => OrganisationsFixture::ORGANISATION_A_ID,
                "authkey" => $faker->sha256(),
                "self_signed" => true,
            ]
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists('Servers', ['name' => 'Test Server']);
    }
}
