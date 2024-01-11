<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class FeedsFixture extends TestFixture
{
    public $connection = 'test';

    public const FEED_1_ID = 1000;
    public const FEED_1_NAME = 'test-feed-1';

    public const FEED_2_ID = 2000;
    public const FEED_2_NAME = 'test-feed-2';

    public function init(): void
    {
        $faker = \Faker\Factory::create();

        $this->records = [
            [
                'id' => self::FEED_1_ID,
                'name' => self::FEED_1_NAME,
                'provider' => 'test-provider',
                'url' => 'http://localhost/test-feed-1'
            ],
            [
                'id' => self::FEED_2_ID,
                'name' => self::FEED_2_NAME,
                'provider' => 'test-provider',
                'url' => 'http://localhost/test-feed-2'
            ]
        ];
        parent::init();
    }
}
