<?php

return
    [
        'paths' => [
            'migrations' => '/app/Db/Migrations',
            'seeds' => '/app/Db/Seeds'
        ],
        'environments' => [
            'default_migration_table' => 'phinxlog',
            'default_environment' => 'production',
            'production' => [
                'adapter' => 'pgsql',
                'host' => '127.0.0.1',
                'name' => 'misp',
                'user' => 'misp',
                'pass' => 'blah',
                'port' => '5432',
                'charset' => 'utf8',
            ],
            'development' => [
                'adapter' => 'pgsql',
                'host' => '127.0.0.1',
                'name' => 'misp_dev',
                'user' => 'misp',
                'pass' => 'blah',
                'port' => '5432',
                'charset' => 'utf8',
            ],
            'testing' => [
                'adapter' => 'pgsql',
                'host' => '127.0.0.1',
                'name' => 'misp_test',
                'user' => 'misp',
                'pass' => 'blah',
                'port' => '5432',
                'charset' => 'utf8',
            ]
        ],
        'version_order' => 'creation'
    ];
