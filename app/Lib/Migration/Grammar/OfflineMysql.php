<?php

App::uses('MysqlExtended', 'Model/Datasource/Database');
App::uses('OfflineConnection', 'Migration/Grammar');

/**
 * A MySQL datasource that renders DDL without connecting to anything.
 *
 * Exists so that `migrationApply --dry-run` can print the MySQL rendering of a
 * migration on a host that speaks only PostgreSQL, which is the mirror image of
 * the case that made this necessary in the first place (see OfflinePostgres).
 *
 * MysqlExtended rather than Mysql because MISP never runs vanilla Mysql - every
 * datasource it ships is MysqlExtended or a subclass - and MysqlExtended::value()
 * short-circuits integers instead of quoting them, which shows up in rendered
 * defaults.
 *
 * @see OfflinePostgres
 */
class OfflineMysql extends MysqlExtended
{
    /**
     * Deliberately does not call parent::__construct(): that calls enabled(),
     * which needs pdo_mysql present, and then connect().
     */
    public function __construct()
    {
        $this->_connection = new OfflineConnection();
        // name() would otherwise reach the Cache facade for its method cache.
        $this->cacheMethods = false;
        $this->config = array('prefix' => '', 'database' => 'misp');
    }
}
