<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class WarninglistEntriesFixture extends TestFixture
{
    public const WARNINGLIST_ENTRY_1_ID = 1;
    public const WARNINGLIST_ENTRY_2_ID = 2;
    public const WARNINGLIST_ENTRY_3_ID = 3;
    public const WARNINGLIST_ENTRY_4_ID = 4;
    public const WARNINGLIST_ENTRY_5_ID = 5;
    public const WARNINGLIST_ENTRY_6_ID = 6;
    public const WARNINGLIST_ENTRY_7_ID = 7;
    public const WARNINGLIST_ENTRY_8_ID = 8;
    public const WARNINGLIST_ENTRY_9_ID = 9;
    public const WARNINGLIST_ENTRY_10_ID = 10;
    public const WARNINGLIST_ENTRY_11_ID = 11;
    public const WARNINGLIST_ENTRY_12_ID = 12;
    public const WARNINGLIST_ENTRY_13_ID = 13;
    public const WARNINGLIST_ENTRY_14_ID = 14;

    public function init(): void
    {
        $this->records = [
            // enabled
            [
                'id' => self::WARNINGLIST_ENTRY_1_ID,
                'warninglist_id' => WarninglistsFixture::WARNINGLIST_CIDR_1_ID,
                'value' => '1.1.1.0/24',
                'comment' => '',
            ],
            [
                'id' => self::WARNINGLIST_ENTRY_2_ID,
                'warninglist_id' => WarninglistsFixture::WARNINGLIST_CIDR_1_ID,
                'value' => '2.2.0.0/16',
                'comment' => '',
            ],
            [
                'id' => self::WARNINGLIST_ENTRY_3_ID,
                'warninglist_id' => WarninglistsFixture::WARNINGLIST_CIDR_1_ID,
                'value' => '1.1.1.0/32',
                'comment' => '',
            ],
            // disabled
            [
                'id' => self::WARNINGLIST_ENTRY_4_ID,
                'warninglist_id' => WarninglistsFixture::WARNINGLIST_CIDR_2_ID,
                'value' => '4.4.4.0/24',
                'comment' => '',
            ],
            // hostname
            [
                'id' => self::WARNINGLIST_ENTRY_5_ID,
                'warninglist_id' => WarninglistsFixture::WARNINGLIST_HOSTNAME_ID,
                'value' => 'vm.misp-project.org',
                'comment' => '',
            ],
            // substr
            [
                'id' => self::WARNINGLIST_ENTRY_6_ID,
                'warninglist_id' => WarninglistsFixture::WARNINGLIST_SUBSTR_ID,
                'value' => 'misp',
                'comment' => '',
            ],
            // str
            [
                'id' => self::WARNINGLIST_ENTRY_7_ID,
                'warninglist_id' => WarninglistsFixture::WARNINGLIST_STR_ID,
                'value' => 'vm.misp-project.org',
                'comment' => '',
            ],
            // regex
            [
                'id' => self::WARNINGLIST_ENTRY_8_ID,
                'warninglist_id' => WarninglistsFixture::WARNINGLIST_REGEX_ID,
                'value' => '/misp-[a-z]\.org$/',
                'comment' => '',
            ],
        ];

        // TODO import warninglists from files to have larger datasets

        parent::init();
    }
}
