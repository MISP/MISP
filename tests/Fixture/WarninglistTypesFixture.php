<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class WarninglistTypesFixture extends TestFixture
{
    public const WARNINGLIST_TYPE_1_ID = 1;
    public const WARNINGLIST_TYPE_2_ID = 2;
    public const WARNINGLIST_TYPE_3_ID = 3;
    public const WARNINGLIST_TYPE_4_ID = 4;
    public const WARNINGLIST_TYPE_5_ID = 5;
    public const WARNINGLIST_TYPE_6_ID = 6;
    public const WARNINGLIST_TYPE_7_ID = 7;
    public const WARNINGLIST_TYPE_8_ID = 8;
    public const WARNINGLIST_TYPE_9_ID = 9;
    public const WARNINGLIST_TYPE_10_ID = 10;

    public function init(): void
    {
        $this->records = [
            // CIDR
            [
                'id' => self::WARNINGLIST_TYPE_1_ID,
                'warninglist_id' => WarninglistsFixture::WARNINGLIST_CIDR_1_ID,
                'type' => 'ip-src',
            ],
            [
                'id' => self::WARNINGLIST_TYPE_2_ID,
                'warninglist_id' => WarninglistsFixture::WARNINGLIST_CIDR_1_ID,
                'type' => 'ip-dst',
            ],
            [
                'id' => self::WARNINGLIST_TYPE_3_ID,
                'warninglist_id' => WarninglistsFixture::WARNINGLIST_CIDR_1_ID,
                'type' => 'domain|ip',
            ],
            // HOSTNAME
            [
                'id' => self::WARNINGLIST_TYPE_4_ID,
                'warninglist_id' => WarninglistsFixture::WARNINGLIST_HOSTNAME_ID,
                'type' => 'url',
            ],
            [
                'id' => self::WARNINGLIST_TYPE_5_ID,
                'warninglist_id' => WarninglistsFixture::WARNINGLIST_HOSTNAME_ID,
                'type' => 'domain|ip',
            ],
            [
                'id' => self::WARNINGLIST_TYPE_6_ID,
                'warninglist_id' => WarninglistsFixture::WARNINGLIST_HOSTNAME_ID,
                'type' => 'hostname',
            ],
            [
                'id' => self::WARNINGLIST_TYPE_7_ID,
                'warninglist_id' => WarninglistsFixture::WARNINGLIST_HOSTNAME_ID,
                'type' => 'domain',
            ],
            // SUBSTR
            [
                'id' => self::WARNINGLIST_TYPE_8_ID,
                'warninglist_id' => WarninglistsFixture::WARNINGLIST_SUBSTR_ID,
                'type' => 'domain',
            ],
            // STR
            [
                'id' => self::WARNINGLIST_TYPE_9_ID,
                'warninglist_id' => WarninglistsFixture::WARNINGLIST_STR_ID,
                'type' => 'domain',
            ],
            // REGEX
            [
                'id' => self::WARNINGLIST_TYPE_10_ID,
                'warninglist_id' => WarninglistsFixture::WARNINGLIST_REGEX_ID,
                'type' => 'domain',
            ],
        ];

        parent::init();
    }
}
