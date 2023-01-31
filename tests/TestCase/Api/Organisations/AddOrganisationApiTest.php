<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Organisations;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;

class AddOrganisationApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/organisations/add';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testAddOrganisation(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $faker = \Faker\Factory::create();
        $uuid = $faker->uuid;

        $this->post(
            self::ENDPOINT,
            [
                'name' => 'Test Organisation',
                'description' => $faker->text,
                'uuid' => $uuid,
                'url' => 'http://example.com',
                'nationality' => 'US',
                'sector' => 'sector',
                'type' => 'type',
            ]
        );

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"uuid": "%s"', $uuid));
        $this->assertDbRecordExists('Organisations', ['uuid' => $uuid]);
    }

    public function testAddOrganisationNotAllowedAsRegularUser(): void
    {
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);

        $faker = \Faker\Factory::create();
        $uuid = $faker->uuid;

        $this->post(
            self::ENDPOINT,
            [
                'name' => 'Test Organisation',
                'description' => $faker->text,
                'uuid' => $uuid,
                'url' => 'http://example.com',
                'nationality' => 'US',
                'sector' => 'sector',
                'type' => 'type',
            ]
        );

        $this->assertResponseCode(405);
        $this->assertDbRecordNotExists('Organisations', ['uuid' => $uuid]);
    }
}
