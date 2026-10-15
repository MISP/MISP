<?php

/**
 * Stands in for the PDO handle when a grammar renders for an engine this host
 * cannot connect to.
 *
 * DboSource::value() is the only part of the rendering path that reaches the
 * connection, and all it asks of it is quote(). Supplying that - rather than
 * overriding value() in the offline datasource - is what keeps the offline
 * rendering honest: every driver quirk above the quoting layer is still the
 * real driver's, so what --dry-run prints is what the engine would be sent.
 *
 * Both drivers quote the same way: single quotes, doubled to escape.
 *
 * The MySQL grammar also asks it for the server version, which picks the
 * collation a token renders as (see Collation).
 *
 * @see OfflineMysql
 * @see OfflinePostgres
 */
class OfflineConnection
{
    /**
     * @var string|null
     */
    private $serverVersion;

    /**
     * @param string|null $serverVersion What the server this stands in for would report.
     */
    public function __construct($serverVersion = null)
    {
        $this->serverVersion = $serverVersion;
    }

    /**
     * @param int $attribute
     * @return string|null The server version for PDO::ATTR_SERVER_VERSION, else null.
     */
    public function getAttribute($attribute)
    {
        return $attribute === PDO::ATTR_SERVER_VERSION ? $this->serverVersion : null;
    }

    /**
     * @param mixed $value
     * @param int|null $type Accepted and ignored, to match PDO::quote()'s signature.
     * @return string
     */
    public function quote($value, $type = null)
    {
        return "'" . str_replace("'", "''", (string)$value) . "'";
    }
}
