<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class ObjectTemplatesFixture extends TestFixture
{
    public $connection = 'test';

    public const OBJECT_TEMPLATE_1_ID = 1;
    public const OBJECT_TEMPLATE_1_NAME = 'object template 1 (active)';
    public const OBJECT_TEMPLATE_2_ID = 2;
    public const OBJECT_TEMPLATE_2_NAME = 'object template 2 (deactivated)';

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::OBJECT_TEMPLATE_1_ID,
                'user_id' => UsersFixture::USER_ADMIN_ID,
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'uuid' => $faker->uuid(),
                'name' => self::OBJECT_TEMPLATE_1_NAME,
                'meta_category' => 'test',
                'description' => 'test description (active)',
                'version' => '1',
                'requirements' => json_encode(['requiredOneOf' => ['ip-src', 'ip-dst']]),
                'fixed' => 0,
                'active' => 1
            ],
            [
                'id' => self::OBJECT_TEMPLATE_2_ID,
                'user_id' => UsersFixture::USER_ADMIN_ID,
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'uuid' => $faker->uuid(),
                'name' => self::OBJECT_TEMPLATE_2_NAME,
                'meta_category' => 'test',
                'description' => 'test description',
                'version' => '1',
                'requirements' => json_encode([]),
                'fixed' => 0,
                'active' => 0
            ]
        ];
        parent::init();
    }
}
