<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class ServersFixture extends TestFixture
{
    public $connection = 'test';

    public const SERVER_A_ID = 1000;
    public const SERVER_A_NAME = 'Server A';

    public const SERVER_B_ID = 2000;
    public const SERVER_B_NAME = 'Server B';

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::SERVER_A_ID,
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'name' => self::SERVER_A_NAME,
                'url' => $faker->url,
                'authkey' => $faker->sha1(),
                'push' => true,
                'pull' => true,
                'push_sightings' => true,
                'push_galaxy_clusters' => true,
                'pull_galaxy_clusters' => true,
                'organization' => 'Org A',
                'remote_org_id' => $faker->numberBetween(1000, 2000),
                'publish_without_email' => true,
                'unpublish_event' => true,
                'self_signed' => true,
                'pull_rules' => json_encode([]),
                'push_rules' => json_encode([]),
                'internal' => false,
                'skip_proxy' => false,
                'remove_missing_tags' => false,
                'caching_enabled' => false,
                'priority' => 1,
            ],
            [
                'id' => self::SERVER_B_ID,
                'org_id' => OrganisationsFixture::ORGANISATION_B_ID,
                'name' => self::SERVER_B_NAME,
                'url' => $faker->url,
                'authkey' => $faker->sha1(),
                'push' => true,
                'pull' => true,
                'push_sightings' => true,
                'push_galaxy_clusters' => true,
                'pull_galaxy_clusters' => true,
                'organization' => 'Org B',
                'remote_org_id' => $faker->numberBetween(1000, 2000),
                'publish_without_email' => true,
                'unpublish_event' => true,
                'self_signed' => true,
                'pull_rules' => json_encode([]),
                'push_rules' => json_encode([]),
                'internal' => false,
                'skip_proxy' => false,
                'remove_missing_tags' => false,
                'caching_enabled' => false,
                'priority' => 1,
            ]
        ];
        parent::init();
    }
}
