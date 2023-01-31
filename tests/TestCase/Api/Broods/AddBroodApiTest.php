<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Broods;

use Cake\TestSuite\TestCase;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;

class AddBroodApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/broods/add';

    protected $fixtures = [
        'app.Organisations',
        'app.Individuals',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
        'app.Broods'
    ];

    public function testAddBrood(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);

        $faker = \Faker\Factory::create();
        $uuid = $faker->uuid;

        $this->post(
            self::ENDPOINT,
            [
                'uuid' => $uuid,
                'name' => 'Brood A',
                'url' => $faker->url,
                'description' => $faker->text,
                'organisation_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'trusted' => true,
                'pull' => true,
                'skip_proxy' => true,
                'authkey' => $faker->sha1,
            ]
        );

        $this->assertResponseOk();
        $this->assertResponseContains(sprintf('"uuid": "%s"', $uuid));
        $this->assertDbRecordExists('Broods', ['uuid' => $uuid]);
    }

    public function testAddBroodNotAllowedAsRegularUser(): void
    {
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);

        $faker = \Faker\Factory::create();
        $uuid = $faker->uuid;

        $this->post(
            self::ENDPOINT,
            [
                'uuid' => $uuid,
                'name' => 'Brood A',
                'url' => $faker->url,
                'description' => $faker->text,
                'organisation_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'trusted' => true,
                'pull' => true,
                'skip_proxy' => true,
                'authkey' => $faker->sha1,
            ]
        );

        $this->assertResponseCode(405);
        $this->assertDbRecordNotExists('Broods', ['uuid' => $uuid]);
    }
}
