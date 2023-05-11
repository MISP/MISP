<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class AllowedlistsFixture extends TestFixture
{
    public $connection = 'test';

    public const ALLOWED_LIST_1_ID = 1000;
    public const ALLOWED_LIST_2_ID = 2000;

    public function init(): void
    {
        $this->records = [
            [
                'id' => self::ALLOWED_LIST_1_ID,
                'name' => '/192.168.0.\d+/',
            ],
            [
                'id' => self::ALLOWED_LIST_2_ID,
                'name' => '/192.168.1.\d+/',
            ]
        ];
        parent::init();
    }
}
