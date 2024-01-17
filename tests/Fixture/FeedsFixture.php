<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class FeedsFixture extends TestFixture
{
    public $connection = 'test';

    public const FEED_1_ID = 1000;
    public const FEED_1_NAME = 'test-feed-1';
    public const FEED_1_URL = 'http://feed1.local/misp/test-feed-1';

    public const FEED_2_ID = 2000;
    public const FEED_2_NAME = 'test-feed-2';
    public const FEED_2_URL = 'http://feed2.local/misp/test-feed-2';

    public function init(): void
    {
        $this->records = [
            [
                'id' => self::FEED_1_ID,
                'name' => self::FEED_1_NAME,
                'provider' => 'test-provider',
                'url' => self::FEED_1_URL,
                "source_format" => 'misp',
                'enabled' => true,
            ],
            [
                'id' => self::FEED_2_ID,
                'name' => self::FEED_2_NAME,
                'provider' => 'test-provider',
                'url' => self::FEED_2_URL,
                "source_format" => 'misp',
                'enabled' => false,
            ]
        ];
        parent::init();
    }
}
