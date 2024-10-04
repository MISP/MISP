<?php
/**
 * This is the database configuration file. MISP will use this configuration to connect to the database.
 * 
 * datasource => The name of a supported datasource; valid options are as follows:
 *     Database/Mysql                 - default MySQL / MariaDB datasource,
 *     Database/MysqlExtended         - MySQL / MariaDB datasource with some extensions for performance,
 *     Database/MysqlObserver         - MySQL / MariaDB datasource with additional MISP specific comments in the logs,
 *     Database/MysqlObserverExtended - Combines the improvements of the above two datasources,
 *
 * persistent => true / false
 * Determines whether or not the database should use a persistent connection
 *
 * host =>
 * the host you connect to the database. To add a socket or port number, use port => #
 *
 * prefix =>
 * Uses the given prefix for all the tables in this database.  This setting can be overridden
 * on a per-table basis with the Model::$tablePrefix property.
 *
 * encoding =>
 * For MySQL, Postgres specifies the character encoding to use when connecting to the
 * database. Uses database default if not specified.
 *
 * unix_socket =>
 * For MySQL to connect via socket specify the `unix_socket` parameter instead of `host` and `port`
 * 
 * PDO::ATTR_STRINGIFY_FETCHES => true is required for compatibility with the MISP standard / pre 2.5 behaviour.
 */
class DATABASE_CONFIG {

    public $default = [
        'datasource' => 'Database/MysqlObserverExtended',
        'persistent' => false,
        'host' => 'localhost',
        'login' => 'db login',
        'port' => 3306,
        'password' => 'db password',
        'database' => 'misp',
        'prefix' => '',
        'encoding' => 'utf8',
        'flags' => [
            PDO::ATTR_STRINGIFY_FETCHES => true
        ]
	];
}
