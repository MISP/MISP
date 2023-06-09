<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class SightingdbsFixture extends TestFixture
{
    public $connection = 'test';

    public const SDB_1_ID = 1000;
    public const SDB_2_ID = 2000;

    public function init(): void
    {
        $this->records = [
            [
                'id' => self::SDB_1_ID,
                'name' => 'sightingdb1',
                'description' => 'test db 1',
                'host' => 'sightingdb.misp-project.org',
                'port' => 27015,
                'enabled' => 1,
                'skip_proxy' => 0,
                'ssl_skip_verification' => 0,
                'namespace' => 'misp1'
            ],
            [
                'id' => self::SDB_2_ID,
                'name' => 'sightingdb2',
                'description' => 'test db 2',
                'host' => 'sightingdb2.misp-project.org',
                'port' => 27015,
                'enabled' => 1,
                'skip_proxy' => 0,
                'ssl_skip_verification' => 0,
                'namespace' => 'misp2'
            ]
        ];
        parent::init();
    }
}
