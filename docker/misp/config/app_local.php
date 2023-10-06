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
    /*
     * Debug Level:
     *
     * Production Mode:
     * false: No error messages, errors, or warnings shown.
     *
     * Development Mode:
     * true: Errors and warnings shown.
     */
    'debug' => filter_var(env('DEBUG', false), FILTER_VALIDATE_BOOLEAN),

    /*
     * Security and encryption configuration
     *
     * - salt - A random string used in security hashing methods.
     *   The salt value is also used as the encryption key.
     *   You should treat it as extremely sensitive data.
     */
    'Security' => [
        'salt' => env('SECURITY_SALT', '__SALT__'),
    ],

    /*
     * Connection information used by the ORM to connect
     * to your application's datastores.
     *
     * See app.php for more configuration options.
     */
    'Datasources' => [
        'default' => [
            'host' => 'db',
            'username' => env('MISP_DB_USER', 'misp'),
            'password' => env('MISP_DB_PASSWORD'),
            'database' => env('MISP_DB', 'misp3'),
        ],
        /*
         * The test connection is used during the test suite.
         */
        'test' => [
            'host' => 'db',
            'username' => 'misp',
            'password' => 'misp',
            'database' => 'misp3_test',
        ],
    ],

    /*
     * Email configuration.
     *
     * Host and credential configuration in case you are using SmtpTransport
     *
     * See app.php for more configuration options.
     */
    'EmailTransport' => [
        'default' => [
            'host' => 'mail',
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
