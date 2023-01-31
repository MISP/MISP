<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class IndividualsFixture extends TestFixture
{
    public $connection = 'test';

    public const INDIVIDUAL_ADMIN_ID = 1;
    public const INDIVIDUAL_SYNC_ID = 2;
    public const INDIVIDUAL_ORG_ADMIN_ID = 3;
    public const INDIVIDUAL_REGULAR_USER_ID = 4;
    public const INDIVIDUAL_A_ID = 5;

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::INDIVIDUAL_ADMIN_ID,
                'uuid' => $faker->uuid(),
                'email' => $faker->email(),
                'first_name' => $faker->firstName,
                'last_name' => $faker->lastName,
                'position' => 'admin',
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
            [
                'id' => self::INDIVIDUAL_SYNC_ID,
                'uuid' => $faker->uuid(),
                'email' => $faker->email(),
                'first_name' => $faker->firstName,
                'last_name' => $faker->lastName,
                'position' => 'sync',
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
            [
                'id' => self::INDIVIDUAL_ORG_ADMIN_ID,
                'uuid' => $faker->uuid(),
                'email' => $faker->email(),
                'first_name' => $faker->firstName,
                'last_name' => $faker->lastName,
                'position' => 'org_admin',
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
            [
                'id' => self::INDIVIDUAL_REGULAR_USER_ID,
                'uuid' => $faker->uuid(),
                'email' => $faker->email(),
                'first_name' => $faker->firstName,
                'last_name' => $faker->lastName,
                'position' => 'user',
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
            [
                'id' => self::INDIVIDUAL_A_ID,
                'uuid' => $faker->uuid(),
                'email' => $faker->email(),
                'first_name' => $faker->firstName,
                'last_name' => $faker->lastName,
                'position' => 'user',
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ]
        ];
        parent::init();
    }
}
