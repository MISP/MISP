<?php
/*
 * Local configuration file to provide any overrides to your app.php configuration.
 * Copy and save this file as app_local.php and make changes as required.
 * Note: It is not recommended to commit files with credentials such as app_local.php
 * into source code version control.
 */
$db = [
    'username' => env('CEREBRATE_DB_USERNAME', 'cerebrate'),
    'password' => env('CEREBRATE_DB_PASSWORD', ''),
    'host' => env('CEREBRATE_DB_HOST', 'localhost'),
    'database' => env('CEREBRATE_DB_NAME', 'cerebrate'),
    // You can use a DSN string to set the entire configuration
    'url' => env('CEREBRATE_DB_URL', null)
];

// non-default port can be set on demand - otherwise the DB driver will choose the default
if (!empty(env('CEREBRATE_DB_PORT'))) {
    $db['port'] = env('CEREBRATE_DB_PORT');
}

// If not using the default 'public' schema with the PostgreSQL driver set it here.
if (!empty(env('CEREBRATE_DB_SCHEMA'))) {
    $db['schema'] = env('CEREBRATE_DB_SCHEMA');
}

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
        'default' => $db,
        /*
         * The test connection is used during the test suite.
         */
        'test' => [
            'host' => 'localhost',
            //'port' => 'non_standard_port_number',
            'username' => 'my_app',
            'password' => 'secret',
            'database' => 'test_myapp',
            //'schema' => 'myapp',
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
            'host' => 'localhost',
            'port' => 25,
            'username' => null,
            'password' => null,
            'client' => null,
            'url' => env('EMAIL_TRANSPORT_DEFAULT_URL', null),
        ],
    ],
    'Cerebrate' => [
	'open' => [],
    'dark' => 0
    ]
];
