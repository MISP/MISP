<?php
/**
 * Collation tokens and what each is called per server: the one place a
 * migration's `collate` token becomes a collation name.
 */

require_once __DIR__ . '/MigrationSchemaStubs.php';

use PHPUnit\Framework\TestCase;

class CollationTest extends TestCase
{
    const MARIADB = '10.11.14-MariaDB-0ubuntu0.24.04.1';

    const MYSQL = '8.4.6';

    public static function supportedServers()
    {
        return array(
            'MariaDB 10.11 (Ubuntu 24.04)' => array(self::MARIADB, Collation::MARIADB, '10.11'),
            'MariaDB 10.11, old handshake prefix' => array('5.5.5-10.11.6-MariaDB-log', Collation::MARIADB, '10.11'),
            'MariaDB 11.8' => array('11.8.2-MariaDB', Collation::MARIADB, '11.8'),
            'MySQL 8.4' => array(self::MYSQL, Collation::MYSQL, '8.4'),
            'Percona Server 8.4' => array('8.4.3-3', Collation::MYSQL, '8.4'),
            'MySQL 9.1' => array('9.1.0', Collation::MYSQL, '9.1'),
        );
    }

    /**
     * @dataProvider supportedServers
     */
    public function testTheServerIsReadFromItsVersion($version, $family, $release)
    {
        $this->assertSame(array($family, $release), Collation::server($version));
    }

    public function testEachTokenResolvesPerFamily()
    {
        $expected = array(
            Collation::CI => array(
                self::MARIADB => array('charset' => 'utf8mb4', 'collate' => 'utf8mb4_uca1400_ai_ci'),
                self::MYSQL => array('charset' => 'utf8mb4', 'collate' => 'utf8mb4_unicode_520_ci'),
            ),
            Collation::BIN => array(
                self::MARIADB => array('charset' => 'utf8mb4', 'collate' => 'utf8mb4_bin'),
                self::MYSQL => array('charset' => 'utf8mb4', 'collate' => 'utf8mb4_bin'),
            ),
            Collation::ASCII => array(
                self::MARIADB => array('charset' => 'ascii', 'collate' => 'ascii_bin'),
                self::MYSQL => array('charset' => 'ascii', 'collate' => 'ascii_bin'),
            ),
        );
        foreach ($expected as $token => $byServer) {
            foreach ($byServer as $version => $resolved) {
                $this->assertSame($resolved, Collation::forServer($token, $version), "$token on $version");
            }
            $this->assertSame($resolved['charset'], Collation::charset($token));
        }
        $this->assertSame(
            array(Collation::MARIADB => 'utf8mb4_uca1400_ai_ci', Collation::MYSQL => 'utf8mb4_unicode_520_ci'),
            Collation::byFamily(Collation::CI)
        );
    }

    public static function unsupportedServers()
    {
        return array(
            'MariaDB 10.10' => array('10.10.7-MariaDB', 'This database server is MariaDB 10.10.'),
            'MariaDB 10.6 (Ubuntu 22.04)' => array('10.6.18-MariaDB-0ubuntu0.22.04.1', 'This database server is MariaDB 10.6.'),
            'MySQL 8.0 (Ubuntu 24.04)' => array('8.0.43-0ubuntu0.24.04.2', 'This database server is MySQL 8.0.'),
            'MySQL 8.3' => array('8.3.0', 'This database server is MySQL 8.3.'),
            'MySQL 5.7' => array('5.7.44-log', 'This database server is MySQL 5.7.'),
            'no version' => array(null, 'reports its version as ""'),
            'unreadable' => array('unknown', 'reports its version as "unknown"'),
        );
    }

    /**
     * Even BIN and ASCII, which no supported server names differently: one
     * rule, the same one the preflight applies.
     *
     * @dataProvider unsupportedServers
     */
    public function testAServerBelowTheFloorDefersEveryToken($version, $message)
    {
        foreach (array(Collation::CI, Collation::BIN, Collation::ASCII) as $token) {
            try {
                Collation::forServer($token, $version);
                $this->fail("$token resolved on $version");
            } catch (MigrationDeferredException $e) {
                $this->assertStringContainsString($message, $e->getMessage());
                $this->assertStringContainsString(
                    'MISP 3.0 needs MariaDB 10.11 or later, or MySQL 8.4 or later.',
                    $e->getMessage()
                );
            }
        }
    }

    public function testOnlyTheThreeTokensAreKnown()
    {
        $this->assertTrue(Collation::isToken(Collation::CI));
        $this->assertTrue(Collation::isToken('<Ci>'));
        $this->assertFalse(Collation::isToken('utf8mb4_bin'));
        $this->assertFalse(Collation::isToken('<>'));
        $this->assertFalse(Collation::isToken(null));

        foreach (array('<Ci>', '<ci>', '<UTF8>', 'utf8mb4_bin') as $value) {
            try {
                Collation::forServer($value, self::MARIADB);
                $this->fail("$value resolved");
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString('Unknown collation token', $e->getMessage());
            }
        }
    }
}
