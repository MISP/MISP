<?php

declare(strict_types=1);

namespace App\Test\TestCase\Api\Cerebrates;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class AddCerebrateApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/cerebrates/add';

    protected $fixtures = [
        'app.Organisations',
        'app.Cerebrates',
        'app.Roles',
        'app.Users',
        'app.AuthKeys'
    ];

    public function testAddCerebrate(): void
    {
        $this->skipOpenApiValidations();
        $faker = \Faker\Factory::create();
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->post(
            self::ENDPOINT,
            [
                // 'id' => CerebratesFixture::SERVER_A_ID,
                'name' => 'Cerebrate Add A',
                'url' => $faker->url(),
                'authkey' => $faker->sha1(),
                // 'open' => 1,
                'org_id' => 1,
                'pull_orgs' => true,
                'pull_sharing_groups' => true,
                'self_signed' => true,
                'cert_file' => false,
                'client_cert_file' => false,
                // 'internal' => 1,
                'skip_proxy' => false,
                'description' => $faker->sentence()
            ]
        );

        $this->assertResponseOk();
        $this->assertResponseContains('"name": "Cerebrate Add A"');
        $this->assertDbRecordExists('Cerebrates', ['name' => 'Cerebrate Add A']);
    }

    public function testAddCerebrateNotAllowedAsRegularUser(): void
    {
        $this->skipOpenApiValidations();
        $faker = \Faker\Factory::create();
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $this->post(
            self::ENDPOINT,
            [
                // 'id' => CerebratesFixture::SERVER_A_ID,
                'name' => 'Cerebrate Add A',
                'url' => $faker->url(),
                'authkey' => $faker->sha1(),
                // 'open' => 1,
                'org_id' => 1,
                'pull_orgs' => true,
                'pull_sharing_groups' => true,
                'self_signed' => true,
                'cert_file' => false,
                'client_cert_file' => false,
                // 'internal' => 1,
                'skip_proxy' => false,
                'description' => $faker->sentence()
            ]
        );
        $this->assertResponseCode(405);
        $this->assertDbRecordNotExists('Cerebrates', ['name' => 'Cerebrate Add A']);
    }
}
