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
            'quoteIdentifiers' => true,
        ],
        'test' => [
            'host' => 'db',
            'username' => 'misp',
            'password' => 'misp',
            'database' => 'misp3_test',
            'quoteIdentifiers' => true,
        ],
    ],

    'EmailTransport' => [
        'default' => [
            'host' => env('EMAIL_HOST'),
            'port' => env('EMAIL_PORT'),
            'username' => env('EMAIL_USERNAME'),
            'password' => env('EMAIL_PASSWORD'),
            'className' => 'Smtp',
            'tls' => false
        ],
    ],
    'MISP' => [
        'host_org_id' => 1000,
        'dark' => 0,
        'email' => 'email@example.com',
        'default_event_distribution' => '1',
        'log_paranoid' => false,
        'log_paranoid_include_sql_queries' => false,
        'log_new_audit_compress' => false,
        'log_paranoid_include_post_body' => false,
        'redis_host' => 'redis',
        'redis_port' => 6379,
        'correlation_engine' => 'Default',
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
    ],
    'GnuPG' => [
        'onlyencrypted'     => false,
        'email'             => env('MISP_EMAIL', env('ADMIN_EMAIL')),
        'homedir'           => env('GPG_DIR', '/var/www/.gnupg'),
        'password'          => env('GPG_PASSPHRASE', 'passphrase'),
        'bodyonlyencrypted' => false,
        'sign'              => true,
        'obscure_subject'   => false,
        'binary'            => '/usr/bin/gpg'
    ]
];
