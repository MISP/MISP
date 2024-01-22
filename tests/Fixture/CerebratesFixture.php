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
    public const SERVER_A_URL = 'http://foobar.local';

    public const SERVER_B_ID = 2000;
    public const SERVER_B_NAME = 'Cerebrate B';

    public const CEREBRATE_ORG_LIST = [
        [
            "id" => 1, 
            "uuid" => "1e3492dd-4123-42d6-a0be-8d45951cf6a5", 
            "name" => "default_organisation", 
            "url" => null, 
            "nationality" => null, 
            "sector" => null, 
            "type" => null, 
            "contacts" => null, 
            "created" => "2023-12-09T11:05:30+00:00", 
            "modified" => "2023-12-09T11:05:30+00:00", 
            "tags" => [], 
            "meta_fields" => [], 
            "org_groups" => [], 
            "alignments" => [], 
            "MetaTemplates" => [] 
        ], 
        [
            "id" => 2, 
            "uuid" => "833f8b50-e201-4395-b5d8-ac645594e3d5", 
            "name" => "ORGNAME", 
            "url" => null, 
            "nationality" => "", 
            "sector" => "", 
            "type" => "ADMIN", 
            "contacts" => null, 
            "created" => "2023-12-10T14:09:20+00:00", 
            "modified" => "2023-12-10T14:09:20+00:00", 
            "tags" => [], 
            "meta_fields" => [], 
            "org_groups" => [], 
            "alignments" => [], 
            "MetaTemplates" => [] 
        ] 
     ]; 
    public const CEREBRATE_SG_LIST = [
        [
            "id" => 1, 
            "uuid" => "6b6742b7-babc-42c2-9c9b-4b6b1e81ea38", 
            "name" => "SG_cerebrate_1", 
            "releasability" => "BEL", 
            "description" => "", 
            "organisation_id" => 1, 
            "user_id" => 1, 
            "active" => true, 
            "local" => true, 
            "created" => "2024-01-13T09:33:54+00:00", 
            "modified" => "2024-01-13T09:33:54+00:00", 
            "user" => [
                "id" => 1, 
                "username" => "admin" 
            ], 
            "organisation" => [
                "id" => 1, 
                "uuid" => "1e3492dd-4123-42d6-a0be-8d45951cf6a5", 
                "name" => "default_organisation", 
                "url" => null, 
                "nationality" => null, 
                "sector" => null, 
                "type" => null, 
                "contacts" => null, 
                "created" => "2023-12-09T11:05:30+00:00", 
                "modified" => "2023-12-09T11:05:30+00:00" 
            ], 
            "sharing_group_orgs" => [
                [
                    "id" => 1, 
                    "uuid" => "1e3492dd-4123-42d6-a0be-8d45951cf6a5", 
                    "name" => "default_organisation", 
                    "url" => null, 
                    "nationality" => null, 
                    "sector" => null, 
                    "type" => null, 
                    "contacts" => null, 
                    "created" => "2023-12-09T11:05:30+00:00", 
                    "modified" => "2023-12-09T11:05:30+00:00", 
                    "_joinData" => [
                        "sharing_group_id" => 1, 
                        "organisation_id" => 1, 
                        "deleted" => false, 
                        "extend" => false] 
                ], 
                [
                    "id" => 2, 
                    "uuid" => "833f8b50-e201-4395-b5d8-ac645594e3d5", 
                    "name" => "ORGNAME", 
                    "url" => null, 
                    "nationality" => "", 
                    "sector" => "", 
                    "type" => "ADMIN", 
                    "contacts" => null, 
                    "created" => "2023-12-10T14:09:20+00:00", 
                    "modified" => "2023-12-10T14:09:20+00:00", 
                    "_joinData" => [
                        "sharing_group_id" => 1, 
                        "organisation_id" => 2, 
                        "deleted" => false, 
                        "extend" => false] 
                    ] 
                ] 
            ]
        ];

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
                'url' => self::SERVER_A_URL,
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
