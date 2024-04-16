<?php
declare(strict_types=1);

namespace App\Test\TestCase\Api\Organisations;

use App\Test\Fixture\AuthKeysFixture;
use App\Test\Fixture\OrganisationsFixture;
use App\Test\Helper\ApiTestTrait;
use Cake\TestSuite\TestCase;

class AddOrganisationsApiTest extends TestCase
{
    use ApiTestTrait;

    protected const ENDPOINT = '/organisations/add';

    protected $fixtures = [
        'app.Organisations',
        'app.Roles',
        'app.Users',
        'app.AuthKeys',
    ];

    private function addOrganisation(array $org_data): void
    {
        $url = sprintf('%s', self::ENDPOINT);
        $this->post(
            $url,
            $org_data
        );

        $this->assertResponseOk();
        $this->assertDbRecordExists(
            'Organisations',
            $org_data
        );
    }

    private function addNotAllowed(array $org_data): void
    {
        $url = sprintf('%s', self::ENDPOINT);
        $this->post(
            $url,
            $org_data
        );
        $this->assertResponseCode(405);
        $this->assertDbRecordNotExists(
            'Organisations',
            [
                'name' => $org_data['name'],
            ]
        );
    }

    public function testAddOrganisationAsAdmin(): void
    {
        $faker = \Faker\Factory::create();
        $org_data = [
            'uuid' => $faker->uuid(),
            'name' => $faker->text(10),
            'description' => $faker->text(10),
            'nationality' => $faker->countryCode,
            'sector' => 'IT',
            'type' => '',
            'contacts' => '',
            'local' => 1,
            'restricted_to_domain' => '',
            'landingpage' => '',
            //'date_created' => $faker->dateTime()->getTimestamp(),
            // 'date_modified' => $faker->dateTime()->getTimestamp(),
            // 'created_by' => 0,
        ];
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $this->addOrganisation($org_data);
    }

    public function testAddNotAllowedAsRegularUser(): void
    {
        $this->setAuthToken(AuthKeysFixture::REGULAR_USER_API_KEY);
        $faker = \Faker\Factory::create();
        $org_data = [
            'uuid' => $faker->uuid(),
            'name' => $faker->text(10),
            'description' => $faker->text(10),
            'nationality' => $faker->countryCode,
            'sector' => 'IT',
            'type' => '',
            'contacts' => '',
            'local' => 1,
            'restricted_to_domain' => '',
            'landingpage' => '',
            //'date_created' => $faker->dateTime()->getTimestamp(),
            // 'date_modified' => $faker->dateTime()->getTimestamp(),
            // 'created_by' => 0,
        ];
        $this->addNotAllowed($org_data);
    }

    public function testAddNotAllowedAsOrgAdmin(): void
    {
        $this->setAuthToken(AuthKeysFixture::ORG_ADMIN_API_KEY); // user from org A
        $faker = \Faker\Factory::create();
        $org_data = [
            'uuid' => $faker->uuid(),
            'name' => $faker->text(10),
            'description' => $faker->text(10),
            'nationality' => $faker->countryCode,
            'sector' => 'IT',
            'type' => '',
            'contacts' => '',
            'local' => 1,
            'restricted_to_domain' => '',
            'landingpage' => '',
            //'date_created' => $faker->dateTime()->getTimestamp(),
            // 'date_modified' => $faker->dateTime()->getTimestamp(),
            // 'created_by' => 0,
        ];
        $this->addNotAllowed($org_data);
    }

    public function testAddNameAlreadyExists(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $faker = \Faker\Factory::create();
        $org_data = [
            'uuid' => $faker->uuid(),
            'name' => 'Organisation A',
            'description' => $faker->text(10),
            'nationality' => $faker->countryCode,
            'sector' => 'DUPLICATE ENTRY',
            'type' => '',
            'contacts' => '',
            'local' => 1,
            'restricted_to_domain' => '',
            'landingpage' => '',
            //'date_created' => $faker->dateTime()->getTimestamp(),
            // 'date_modified' => $faker->dateTime()->getTimestamp(),
            // 'created_by' => 0,
        ];
        $url = sprintf('%s', self::ENDPOINT);
        $this->post(
            $url,
            $org_data
        );
        $this->assertResponseCode(200);
        $this->assertDbRecordNotExists(
            'Organisations',
            [
                'name' => 'Organisation A',
                'sector' => 'DUPLICATE ENTRY',
            ]
        );
    }

    public function testAddUuidAlreadyExists(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $faker = \Faker\Factory::create();
        $org_data = [
            'uuid' => OrganisationsFixture::ORGANISATION_A_UUID,
            'name' => $faker->text(10),
            'description' => $faker->text(10),
            'nationality' => $faker->countryCode,
            'sector' => 'DUPLICATE ENTRY',
            'type' => '',
            'contacts' => '',
            'local' => 1,
            'restricted_to_domain' => '',
            'landingpage' => '',
            //'date_created' => $faker->dateTime()->getTimestamp(),
            // 'date_modified' => $faker->dateTime()->getTimestamp(),
            // 'created_by' => 0,
        ];
        $url = sprintf('%s', self::ENDPOINT);
        $this->post(
            $url,
            $org_data
        );
        $this->assertResponseCode(200);
        $this->assertDbRecordNotExists(
            'Organisations',
            [
                'name' => $org_data['name'],
            ]
        );
    }

    public function testBadUuid(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $faker = \Faker\Factory::create();
        $org_data = [
            'uuid' => '11111111-1111-1111-1111-111111111111',
            'name' => $faker->text(10),
            'description' => $faker->text(10),
            'nationality' => $faker->countryCode,
            'sector' => 'DUPLICATE ENTRY',
            'type' => '',
            'contacts' => '',
            'local' => 1,
            'restricted_to_domain' => '',
            'landingpage' => '',
            //'date_created' => $faker->dateTime()->getTimestamp(),
            // 'date_modified' => $faker->dateTime()->getTimestamp(),
            // 'created_by' => 0,
        ];
        $url = sprintf('%s', self::ENDPOINT);
        $this->post(
            $url,
            $org_data
        );
        $this->assertResponseCode(200);
        $this->assertDbRecordNotExists(
            'Organisations',
            [
                'name' => $org_data['name'],
            ]
        );
    }

    public function testAddLongName(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $faker = \Faker\Factory::create();
        $org_data = [
            'uuid' => $faker->uuid(),
            'name' => $faker->text(400),
            'description' => $faker->text(10),
            'nationality' => $faker->countryCode,
            'sector' => 'IT',
            'type' => '',
            'contacts' => '',
            'local' => 1,
            'restricted_to_domain' => '',
            'landingpage' => '',
            //'date_created' => $faker->dateTime()->getTimestamp(),
            // 'date_modified' => $faker->dateTime()->getTimestamp(),
            // 'created_by' => 0,
        ];
        $url = sprintf('%s', self::ENDPOINT);
        $this->post(
            $url,
            $org_data
        );
        $this->assertResponseCode(200);
        $this->assertDbRecordNotExists(
            'Organisations',
            [
                'name' => $org_data['name'],
            ]
        );
    }

    public function testAddCreatedBy(): void
    {
        $this->setAuthToken(AuthKeysFixture::ADMIN_API_KEY);
        $faker = \Faker\Factory::create();
        $org_data = [
            'uuid' => $faker->uuid(),
            'name' => $faker->text(10),
            'description' => $faker->text(10),
            'nationality' => $faker->countryCode,
            'sector' => 'IT',
            'type' => '',
            'contacts' => '',
            'local' => 1,
            'restricted_to_domain' => '',
            'landingpage' => '',
            //'date_created' => $faker->dateTime()->getTimestamp(),
            // 'date_modified' => $faker->dateTime()->getTimestamp(),
            'created_by' => 1,
        ];
        $url = sprintf('%s', self::ENDPOINT);
        $this->post(
            $url,
            $org_data
        );
        $this->assertResponseCode(200);
        $this->assertDbRecordExists(
            'Organisations',
            [
                'uuid' => $org_data['uuid'],
                'created_by' => AuthKeysFixture::ADMIN_API_ID,
            ]
        );
    }
}
