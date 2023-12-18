<?php
declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

/**
 * CerebratesFixture
 */
class CerebratesFixture extends TestFixture
{

    public const SERVER_A_ID = 1000;
    public const SERVER_A_NAME = 'Cerebrate A';

    public const SERVER_B_ID = 2000;
    public const SERVER_B_NAME = 'Cerebrate B';

    /**
     * Init method
     *
     * @return void
     */
    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::SERVER_A_ID,
                'name' => self::SERVER_A_NAME,
                'url' => $faker->url(),
                'authkey' => $faker->sha1(),
                // 'open' => 1,
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'pull_orgs' => true,
                'pull_sharing_groups' => true,
                'self_signed' => true,
                'cert_file' => false,
                'client_cert_file' => false,
                // 'internal' => 1,
                'skip_proxy' => false,
                'description' => $faker->sentence(),
            ],
            [
                'id' => self::SERVER_B_ID,
                'name' => self::SERVER_B_NAME,
                'url' => $faker->url(),
                'authkey' => $faker->sha1(),
                // 'open' => 1,
                'org_id' => OrganisationsFixture::ORGANISATION_B_ID,
                'pull_orgs' => true,
                'pull_sharing_groups' => true,
                'self_signed' => true,
                'cert_file' => false,
                'client_cert_file' => false,
                // 'internal' => 1,
                'skip_proxy' => false,
                'description' => $faker->sentence(),
            ]
        ];
        parent::init();
    }
}
