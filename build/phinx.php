<?php

return
    [
        'paths' => [
            'migrations' => 'Db/Migrations',
            'seeds' => 'Db/Seeds'
        ],
        'environments' => [
            'default_migration_table' => 'phinxlog',
            'default_environment' => 'production',
            'production' => [
                'adapter' => 'pgsql',
                'host' => '127.0.0.1',
                'name' => 'misp',
                'user' => 'misp',
                'pass' => 'example',
                'port' => '5432',
                'charset' => 'utf8',
            ],
            'development' => [
                'adapter' => 'pgsql',
                'host' => '127.0.0.1',
                'name' => 'misp_dev',
                'user' => 'misp',
                'pass' => 'example',
                'port' => '5432',
                'charset' => 'utf8',
            ],
            'testing' => [
                'adapter' => 'pgsql',
                'host' => '127.0.0.1',
                'name' => 'misp_test',
                'user' => 'misp',
                'pass' => 'example',
                'port' => '5432',
                'charset' => 'utf8',
            ]
        ],
        'version_order' => 'creation'
    ];
