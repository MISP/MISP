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
    'debug' => filter_var(env('DEBUG', false), FILTER_VALIDATE_BOOLEAN),
    'Security' => [
        'salt' => env('SECURITY_SALT', '__SALT__'),
    ],
    'Datasources' => [
        'default' => [
            'host' => 'db',
            'username' => env('MISP_DB_USER', 'misp'),
            'password' => env('MISP_DB_PASSWORD'),
            'database' => env('MISP_DB', 'misp3'),
        ],
        'test' => [
            'host' => 'db',
            'username' => 'misp',
            'password' => 'misp',
            'database' => 'misp3_test',
        ],
    ],

    'EmailTransport' => [
        'default' => [
            'host' => env('EMAIL_HOST'),
            'port' => 1025,
            'username' => env('EMAIL_USERNAME'),
            'password' => env('EMAIL_PASSWORD'),
            'className' => 'Smtp',
            'tls' => false
        ],
    ],
    'MISP' => [
        'dark' => 0,
        'email' => 'email@example.com'
    ],
    'BackgroundJobs' => [
        'enabled' => true,
        'redis_host' => 'redis',
        'redis_port' => 6379,
        'redis_password' => '',
        'redis_database' => 1,
        'redis_namespace' => 'background_jobs',
        'max_job_history_ttl' => 86400,
        'supervisor_host' => 'localhost',
        'supervisor_port' => '9001',
        'supervisor_user' => 'supervisor',
        'supervisor_password' => 'supervisor',
    ]
];
