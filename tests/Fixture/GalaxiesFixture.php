<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class GalaxiesFixture extends TestFixture
{
    public $connection = 'test';

    public const GALAXY_1_ID = 1;
    public const GALAXY_1_NAME = 'test-galaxy-fixture-1';
    public const GALAXY_1_UUID = '64771633-a0d4-414a-a27e-b101f91a0270';

    public const GALAXY_2_ID = 2;
    public const GALAXY_2_NAME = 'test-galaxy-fixture-2';
    public const GALAXY_2_UUID = 'edf4c347-f645-4211-9ad3-976395253b80';

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::GALAXY_1_ID,
                'name' => self::GALAXY_1_NAME,
                'uuid' => self::GALAXY_1_UUID,
                'description' => 'test description (disabled)',
                'type' => 'test-galaxy-type',
                'version' => '1',
                'icon' => 'user-secret',
                'namespace' => 'test',
                'enabled' => false,
                'local_only' => false,
                'kill_chain_order' => json_encode(['TEST'])
            ],
            [
                'id' => self::GALAXY_2_ID,
                'name' => self::GALAXY_2_NAME,
                'uuid' => self::GALAXY_2_UUID,
                'description' => 'test description (enabled)',
                'type' => 'test-galaxy-type',
                'version' => '1',
                'icon' => 'user-secret',
                'namespace' => 'test',
                'enabled' => true,
                'local_only' => false,
                'kill_chain_order' => json_encode(['TEST'])
            ]
        ];
        parent::init();
    }
}
