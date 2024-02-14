<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class AttributesFixture extends TestFixture
{
    public $connection = 'test';

    public const ATTRIBUTE_1_ID = 1000;
    public const ATTRIBUTE_1_UUID = '60d515a6-efd1-4ae8-a561-1a5203ec9ade';


    public function init(): void
    {
        $this->records = [
            [
                'id' => self::ATTRIBUTE_1_ID,
                'uuid' => self::ATTRIBUTE_1_UUID,
                'event_id' => EventsFixture::EVENT_1_ID,
                'distribution' => 3,
                'category' => 'Network activity',
                'type' => 'ip-src',
                'value1' => '127.0.0.1',
                'value2' => '',
                'sharing_group_id' => 0,
            ]
        ];
        parent::init();
    }
}
