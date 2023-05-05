<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class EventBlocklistsFixture extends TestFixture
{
    public $connection = 'test';

    public const EVENT_BLOCK_LIST_1_ID = 1;
    public const EVENT_BLOCK_LIST_1_EVENT_UUID = '9a9287e4-6b38-4d7b-b957-801746b71892';

    public const EVENT_BLOCK_LIST_2_ID = 2;
    public const EVENT_BLOCK_LIST_2_EVENT_UUID = '4ca98b8a-5ae5-4c5e-9250-7d2f56e3e6e2';

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::EVENT_BLOCK_LIST_1_ID,
                'event_uuid' => self::EVENT_BLOCK_LIST_1_EVENT_UUID,
                'created' => $faker->dateTime()->getTimestamp(),
                'event_info' => 'Blocked event',
                'event_orgc' => 'ORGC'
            ],
            [
                'id' => self::EVENT_BLOCK_LIST_2_ID,
                'event_uuid' => self::EVENT_BLOCK_LIST_2_EVENT_UUID,
                'created' => $faker->dateTime()->getTimestamp(),
                'event_info' => 'Blocked event',
                'event_orgc' => 'ORGC'
            ]
        ];
        parent::init();
    }
}
