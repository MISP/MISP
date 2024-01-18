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

    public const FEED_3_ID = 3000;
    public const FEED_3_NAME = 'test-feed-3';
    public const FEED_3_URL = 'http://feed3.local/freetext/test-feed-3';

    public function init(): void
    {
        $this->records = [
            [
                'id' => self::FEED_1_ID,
                'name' => self::FEED_1_NAME,
                'provider' => 'test-provider',
                'url' => self::FEED_1_URL,
                "source_format" => 'misp',
                "input_source" => "network",
                "settings" => "[]",
                'enabled' => true,
            ],
            [
                'id' => self::FEED_2_ID,
                'name' => self::FEED_2_NAME,
                'provider' => 'test-provider',
                'url' => self::FEED_2_URL,
                "source_format" => 'misp',
                "input_source" => "network",
                "settings" => "[]",
                'enabled' => false,
            ],
            [
                'id' => self::FEED_3_ID,
                'name' => self::FEED_3_NAME,
                'provider' => 'test-provider',
                'url' => self::FEED_3_URL,
                "source_format" => 'freetext',
                "input_source" => "network",
                "settings" => "{\"csv\":{\"value\":\"\",\"delimiter\":\",\"},\"common\":{\"excluderegex\":\"\"}}",
                'enabled' => true,
            ]
        ];
        parent::init();
    }
}
