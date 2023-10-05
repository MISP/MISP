<?php
/*
 * Local configuration file to provide any overrides to your app.php configuration.
 * Copy and save this file as app_local.php and make changes as required.
 * Note: It is not recommended to commit files with credentials such as app_local.php
 * into source code version control.
 */

// set the baseurl here if you want to set it manually
$baseurl = env('MISP_BASEURL', false);


// Do not modify the this block
$temp = parse_url($baseurl);
$base = empty($temp['path']) ? false : $temp['path'];
// end of block

return [
    'debug' => false,
    'Security' => [
        'salt' => 'foobar',
    ],
    'Datasources' => [
        'default' => [
            'host' => '127.0.0.1',
            'username' => 'misp',
            'password' => 'misp',
            'database' => 'misp3_test',
        ],
        /*
         * The test connection is used during the test suite.
         */
        'test' => [
            'host' => '127.0.0.1',
            'username' => 'misp',
            'password' => 'misp',
            'database' => 'misp3_test',
        ],
    ],
    'EmailTransport' => [
        'default' => [
            'host' => '127.0.0.1',
            'port' => 25,
            'username' => null,
            'password' => null,
            'client' => null,
            'url' => env('EMAIL_TRANSPORT_DEFAULT_URL', null),
        ],
    ],
    'MISP' => [
        'dark' => 0
    ],
    'BackgroundJobs' => [
        'enabled' => true,
        'redis_host' => '127.0.0.1',
        'redis_port' => 6379,
        'redis_password' => '',
        'redis_database' => 1,
        'redis_namespace' => 'background_jobs',
        'max_job_history_ttl' => 86400,
        'supervisor_host' => '127.0.0.1',
        'supervisor_port' => '9001',
        'supervisor_user' => 'supervisor',
        'supervisor_password' => 'supervisor',
    ]
];
