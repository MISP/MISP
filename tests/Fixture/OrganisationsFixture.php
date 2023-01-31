<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class OrganisationsFixture extends TestFixture
{
    public $connection = 'test';

    public const ORGANISATION_A_ID = 1;
    public const ORGANISATION_A_UUID = 'dce5017e-b6a5-4d0d-a0d7-81e9af56c82c';

    public const ORGANISATION_B_ID = 2;
    public const ORGANISATION_B_UUID = '36d22d9a-851e-4838-a655-9999c1d19497';

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::ORGANISATION_A_ID,
                'uuid' => self::ORGANISATION_A_UUID,
                'name' => 'Organisation A',
                'url' => $faker->url,
                'nationality' => $faker->countryCode,
                'sector' => 'IT',
                'type' => '',
                'contacts' => '',
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ],
            [
                'id' => self::ORGANISATION_B_ID,
                'uuid' => $faker->uuid(),
                'name' => self::ORGANISATION_B_UUID,
                'url' => $faker->url,
                'nationality' => $faker->countryCode,
                'sector' => 'IT',
                'type' => '',
                'contacts' => '',
                'created' => $faker->dateTime()->getTimestamp(),
                'modified' => $faker->dateTime()->getTimestamp()
            ]
        ];
        parent::init();
    }
}
