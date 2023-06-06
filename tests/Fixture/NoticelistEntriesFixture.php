<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class NoticelistEntriesFixture extends TestFixture
{
    public $connection = 'test';

    public const NOTICELIST_ENTRY_1_ID = 1;

    public function init(): void
    {
        $this->records = [
            [
                'id' => self::NOTICELIST_ENTRY_1_ID,
                'noticelist_id' => NoticelistsFixture::NOTICELIST_1_ID,
                'data' => json_encode([
                    'scope' => ['attribute'],
                    'field' => ['category'],
                    'value' => ['ip-src'],
                    'tags' => ['test'],
                    'message' => [
                        'en' => 'This a test noticelist entry',
                    ]
                ])
            ]
        ];
        parent::init();
    }
}
