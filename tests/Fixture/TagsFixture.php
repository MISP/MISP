<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class TagsFixture extends TestFixture
{
    public $connection = 'test';

    public const TAG_1_ID = 1000;

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::TAG_1_ID,
                'name' => 'test:tag',
                'colour' => '#000000',
                'exportable' => 1,
                'org_id' => OrganisationsFixture::ORGANISATION_A_ID,
                'user_id' => UsersFixture::USER_ADMIN_ID,
                'hide_tag' => 0,
                'numerical_value' => null,
                'is_galaxy' => 0,
                'is_custom_galaxy' => 0,
                'local_only' => 0
            ]
        ];
        parent::init();
    }
}
