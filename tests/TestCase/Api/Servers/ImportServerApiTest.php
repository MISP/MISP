<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Servers;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class ImportServerApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/servers/import';

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

        $server = [
            "name" => "Test Import Server",
            "url" => $faker->url,
            "authkey" => $faker->sha256(),
            "Organisation" => [
                "name" => "ORGNAME",
                "uuid" => OrganisationsFixture::ORGANISATION_A_UUID
            ]
        ];

        $this->post(
            self::ENDPOINT,
            $server
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists('Servers', ['name' => 'Test Import Server']);
    }
}
