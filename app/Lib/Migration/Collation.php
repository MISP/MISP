<?php

App::uses('MigrationDeferredException', 'Migration');

/**
 * The schema's three collation classes, and what each is called on a given
 * MySQL-family server.
 *
 * A migration names the class - `'collate' => Collation::CI` - and the MySQL
 * grammar resolves it for the server it renders for. PostgreSQL drops it: its
 * columns compare under the database's own collation, and case-insensitive
 * matching there is a lower() index.
 *
 * Resolution goes by version, never by the catalog: MariaDB lists its UCA 14
 * collations in information_schema.COLLATIONS without the charset prefix, so
 * `utf8mb4_uca1400_ai_ci` is not found there even on a server that has it.
 */
class Collation
{
    /** Case- and accent-insensitive, trailing spaces ignored, every character told apart. */
    const CI = '<CI>';

    /** A byte comparison. */
    const BIN = '<BIN>';

    /** A byte comparison, for uuids and hex hashes. */
    const ASCII = '<ASCII>';

    const MARIADB = 'MariaDB';
    const MYSQL = 'MySQL';

    /**
     * @var array The oldest release of each family that is resolved for.
     */
    private static $floors = array(self::MARIADB => '10.11', self::MYSQL => '8.4');

    /**
     * Every MySQL 0900 collation is NO PAD, so a lookup for 'Quasar RAT' would
     * stop finding a stored 'Quasar RAT '. unicode_520_ci is the newest MySQL
     * collation that ignores trailing spaces and still tells emoji apart.
     *
     * @var array
     */
    private static $classes = array(
        self::CI => array(
            'charset' => 'utf8mb4',
            self::MARIADB => 'utf8mb4_uca1400_ai_ci',
            self::MYSQL => 'utf8mb4_unicode_520_ci',
        ),
        self::BIN => array(
            'charset' => 'utf8mb4',
            self::MARIADB => 'utf8mb4_bin',
            self::MYSQL => 'utf8mb4_bin',
        ),
        self::ASCII => array(
            'charset' => 'ascii',
            self::MARIADB => 'ascii_bin',
            self::MYSQL => 'ascii_bin',
        ),
    );

    /**
     * Whether a collate value is written as a token, known or not, so that a
     * misspelt one is refused rather than sent to the server.
     *
     * @param mixed $value
     * @return bool
     */
    public static function isToken($value)
    {
        return is_string($value) && strlen($value) > 2 && $value[0] === '<' && substr($value, -1) === '>';
    }

    /**
     * @param string $token
     * @return string The charset the token's collations belong to.
     * @throws InvalidArgumentException On an unknown token.
     */
    public static function charset($token)
    {
        $definition = self::definition($token);
        return $definition['charset'];
    }

    /**
     * @param string $token
     * @param string|null $serverVersion As the server reports it.
     * @return array 'charset' and 'collate', as that server spells them.
     * @throws InvalidArgumentException On an unknown token.
     * @throws MigrationDeferredException On a server below the floor, or a version that cannot be read.
     */
    public static function forServer($token, $serverVersion)
    {
        $definition = self::definition($token);
        list($family) = self::server($serverVersion);
        return array('charset' => $definition['charset'], 'collate' => $definition[$family]);
    }

    /**
     * @param string $token
     * @return array family => collation.
     * @throws InvalidArgumentException On an unknown token.
     */
    public static function byFamily($token)
    {
        $definition = self::definition($token);
        unset($definition['charset']);
        return $definition;
    }

    /**
     * Which server a version string names, refusing one these collations are
     * not resolved for.
     *
     * @param string|null $serverVersion VERSION(), or PDO's server version.
     * @return array array(family, 'major.minor')
     * @throws MigrationDeferredException
     */
    public static function server($serverVersion)
    {
        // MariaDB before 11 prefixes its handshake version for old clients.
        $version = preg_replace('/^5\.5\.5-/', '', (string)$serverVersion);
        if (!preg_match('/^(\d+)\.(\d+)/', $version, $parts)) {
            throw new MigrationDeferredException(sprintf(
                'The database server reports its version as "%s", which does not say which MySQL-family server it is. %s',
                $serverVersion,
                self::requirement()
            ));
        }
        $family = stripos($version, 'mariadb') !== false ? self::MARIADB : self::MYSQL;
        $release = (int)$parts[1] . '.' . (int)$parts[2];
        if (version_compare($release, self::$floors[$family], '<')) {
            throw new MigrationDeferredException(sprintf(
                'This database server is %s %s. %s Upgrade the database server, then run the update again.',
                $family,
                $release,
                self::requirement()
            ));
        }
        return array($family, $release);
    }

    /**
     * @return string
     */
    private static function requirement()
    {
        return sprintf(
            'MISP 3.0 needs MariaDB %s or later, or MySQL %s or later.',
            self::$floors[self::MARIADB],
            self::$floors[self::MYSQL]
        );
    }

    /**
     * @param string $token
     * @return array
     * @throws InvalidArgumentException
     */
    private static function definition($token)
    {
        if (!is_string($token) || !isset(self::$classes[$token])) {
            throw new InvalidArgumentException(sprintf(
                'Unknown collation token %s. Use Collation::CI, Collation::BIN or Collation::ASCII.',
                var_export($token, true)
            ));
        }
        return self::$classes[$token];
    }
}
