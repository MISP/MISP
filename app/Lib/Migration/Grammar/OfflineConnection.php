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
 * PostgreSQL (standard_conforming_strings on) only doubles a single quote.
 * MySQL's driver also escapes backslashes and control characters, as
 * mysql_real_escape_string() does.
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
     * What mysql_real_escape_string() escapes, and how.
     */
    const MYSQL_ESCAPES = array(
        "\\" => "\\\\",
        "'" => "\\'",
        '"' => '\\"',
        "\0" => '\\0',
        "\n" => '\\n',
        "\r" => '\\r',
        "\x1a" => '\\Z',
    );

    /**
     * @var string|null
     */
    private $serverVersion;

    /**
     * @var bool
     */
    private $backslashEscapes;

    /**
     * @param string|null $serverVersion What the server this stands in for would report.
     * @param bool $backslashEscapes Quote as MySQL's driver does, rather than PostgreSQL's.
     */
    public function __construct($serverVersion = null, $backslashEscapes = false)
    {
        $this->serverVersion = $serverVersion;
        $this->backslashEscapes = $backslashEscapes;
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
        if ($this->backslashEscapes) {
            return "'" . strtr((string)$value, self::MYSQL_ESCAPES) . "'";
        }
        return "'" . str_replace("'", "''", (string)$value) . "'";
    }
}
