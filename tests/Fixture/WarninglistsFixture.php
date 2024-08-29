<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use App\Model\Entity\Warninglist;
use Cake\TestSuite\Fixture\TestFixture;

class WarninglistsFixture extends TestFixture
{
    public $connection = 'test';

    public const WARNINGLIST_CIDR_1_ID = 1;
    public const WARNINGLIST_CIDR_1_NAME = 'disabled cidr warninglist';

    public const WARNINGLIST_CIDR_2_ID = 2;
    public const WARNINGLIST_CIDR_2_NAME = 'enabled cidr warninglist';

    public const WARNINGLIST_HOSTNAME_ID = 3;
    public const WARNINGLIST_HOSTNAME_NAME = 'enabled hostname warninglist';

    public const WARNINGLIST_SUBSTR_ID = 4;
    public const WARNINGLIST_SUBSTR_NAME = 'enabled substr warninglist';

    public const WARNINGLIST_STR_ID = 5;
    public const WARNINGLIST_STR_NAME = 'enabled string warninglist';

    public const WARNINGLIST_REGEX_ID = 6;
    public const WARNINGLIST_REGEX_NAME = 'enabled regex warninglist';

    public function init(): void
    {
        $this->records = [
            [
                'id' => self::WARNINGLIST_CIDR_1_ID,
                'name' => self::WARNINGLIST_CIDR_1_NAME,
                'type' => 'cidr',
                'description' => 'test disabled cidr warninglist description',
                'version' => 1,
                'enabled' => false,
                'default' => false,
                'category' => Warninglist::CATEGORY_FALSE_POSITIVE,
            ],
            [
                'id' => self::WARNINGLIST_CIDR_2_ID,
                'name' => self::WARNINGLIST_CIDR_2_NAME,
                'type' => 'cidr',
                'description' => 'test enabled cidr warninglist description',
                'version' => 1,
                'enabled' => true,
                'default' => false,
                'category' => Warninglist::CATEGORY_KNOWN,
            ],
            [
                'id' => self::WARNINGLIST_HOSTNAME_ID,
                'name' => self::WARNINGLIST_HOSTNAME_NAME,
                'type' => 'hostname',
                'description' => 'test enabled hostname warninglist description',
                'version' => 1,
                'enabled' => true,
                'default' => false,
                'category' => Warninglist::CATEGORY_FALSE_POSITIVE,
            ],
            [
                'id' => self::WARNINGLIST_SUBSTR_ID,
                'name' => self::WARNINGLIST_SUBSTR_NAME,
                'type' => 'hostname',
                'description' => 'test enabled substring warninglist description',
                'version' => 1,
                'enabled' => true,
                'default' => false,
                'category' => Warninglist::CATEGORY_FALSE_POSITIVE,
            ],
            [
                'id' => self::WARNINGLIST_STR_ID,
                'name' => self::WARNINGLIST_STR_NAME,
                'type' => 'hostname',
                'description' => 'test enabled string warninglist description',
                'version' => 1,
                'enabled' => true,
                'default' => false,
                'category' => Warninglist::CATEGORY_FALSE_POSITIVE,
            ],
            [
                'id' => self::WARNINGLIST_REGEX_ID,
                'name' => self::WARNINGLIST_REGEX_NAME,
                'type' => 'hostname',
                'description' => 'test enabled regex warninglist description',
                'version' => 1,
                'enabled' => true,
                'default' => false,
                'category' => Warninglist::CATEGORY_FALSE_POSITIVE,
            ],
        ];
        parent::init();
    }
}
