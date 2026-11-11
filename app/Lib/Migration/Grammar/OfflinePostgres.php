<?php

App::uses('Postgres', 'Model/Datasource/Database');
App::uses('OfflineConnection', 'Migration/Grammar');

/**
 * A PostgreSQL datasource that renders DDL without connecting to anything.
 *
 * Without this, `migrationApply --dry-run` could not show its PostgreSQL half on
 * any normal MISP host. PostgresGrammar renders through the driver's own
 * $columns map, name() and value(), so it needs a Postgres instance - and
 * constructing one runs DboSource::__construct(), which throws
 * MissingConnectionException unless pdo_pgsql is loaded. It is not loaded on a
 * MySQL host, and app/composer.json requires neither PDO extension, so the half
 * of the dry run that actually needs checking is the half that would never
 * print.
 *
 * Rendering is a pure function of the driver's maps and quoting, so skipping the
 * connection costs nothing: the SQL printed here is the SQL a connected Postgres
 * datasource would have produced.
 *
 * @see OfflineMysql
 */
class OfflinePostgres extends Postgres
{
    /**
     * Deliberately does not call parent::__construct(): that calls enabled(),
     * which needs pdo_pgsql present, and then connect().
     */
    public function __construct()
    {
        $this->_connection = new OfflineConnection();
        // name() would otherwise reach the Cache facade for its method cache.
        $this->cacheMethods = false;
        $this->config = array('prefix' => '', 'database' => 'misp', 'schema' => 'public');
    }
}
