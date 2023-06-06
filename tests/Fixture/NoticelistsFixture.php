<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class NoticelistsFixture extends TestFixture
{
    public $connection = 'test';

    public const NOTICELIST_1_ID = 1;
    public const NOTICELIST_1_NAME = 'disabled test noticelist';

    public const NOTICELIST_2_ID = 2;
    public const NOTICELIST_2_NAME = 'enabled test noticelist';

    public function init(): void
    {
        $this->records = [
            [
                'id' => self::NOTICELIST_1_ID,
                'name' => self::NOTICELIST_1_NAME,
                'expanded_name' => 'test disabled noticelist expanded name',
                'ref' => json_encode(['test_ref']),
                'geographical_area' => json_encode(['TEST']),
                'version' => '1',
                'enabled' => false
            ],
            [
                'id' => self::NOTICELIST_2_ID,
                'name' => self::NOTICELIST_2_NAME,
                'expanded_name' => 'test enabled noticelist expanded name',
                'ref' => json_encode(['test_ref']),
                'geographical_area' => json_encode(['TEST']),
                'version' => '1',
                'enabled' => true
            ]
        ];
        parent::init();
    }
}
