<?php
/**
 * The schema target generator: readSchema()-shaped tables in, targets out.
 *
 * Each rule is exercised on a fixture with every other rule list empty, so a
 * failure names the rule. The shipped lists are checked only for shape here;
 * whether they fit the real schema is what `Admin dumpSchemaTargets` checks
 * against a reference, and refuses on.
 */

require_once __DIR__ . '/MigrationSchemaStubs.php';
require_once APPLIBS . 'Migration/BaselineGenerator.php';
require_once APPLIBS . 'Migration/SchemaTargetGenerator.php';

use PHPUnit\Framework\TestCase;

class SchemaTargetGeneratorTest extends TestCase
{
    private static function generator(array $rules = array())
    {
        $empty = array_fill_keys(array(
            'excluded', 'hiddenIds', 'epoch', 'mediumtext', 'overrides', 'ascii', 'kept', 'additions', 'retired',
            'pgsqlReplaced', 'pgsqlOnly',
        ), array());
        return new SchemaTargetGenerator(array_merge($empty, $rules));
    }

    private static function table(array $columns, array $indexes = array(), $collate = 'utf8mb3_bin', array $expressions = array())
    {
        $declared = array();
        foreach ($indexes as $name => $index) {
            $declared[$name] = $index + array('name' => $name, 'unique' => false);
        }
        return array(
            'columns' => $columns,
            'indexes' => $declared,
            'primary' => isset($columns['id']) ? 'id' : null,
            'options' => array('engine' => 'InnoDB', 'collate' => $collate),
            'expressionDefaults' => $expressions,
        );
    }

    private static function id()
    {
        return array('type' => 'integer', 'length' => 11, 'null' => false, 'key' => 'primary');
    }

    // ------------------------------------------------------------- columns

    public function testIdsBecomeSignedBigintWithoutWidth()
    {
        $targets = self::generator(array('hiddenIds' => array('t' => array('lastpulledid'))))->generate(array('t' => self::table(array(
            'id' => self::id(),
            'org_id' => array('type' => 'integer', 'length' => 10, 'unsigned' => true, 'null' => false, 'default' => '0'),
            '1_event_id' => array('type' => 'integer', 'length' => 11, 'null' => true),
            'value_id' => array('type' => 'biginteger', 'length' => 20, 'unsigned' => true, 'null' => false),
            'lastpulledid' => array('type' => 'integer', 'length' => 11, 'null' => true),
            'request_id' => array('type' => 'string', 'length' => 255, 'null' => true),
            'hits' => array('type' => 'integer', 'length' => 10, 'unsigned' => true, 'null' => false),
        ))));
        $columns = $targets['t']['columns'];
        $this->assertSame(array('type' => 'biginteger', 'null' => false, 'key' => 'primary'), $columns['id']);
        $this->assertSame(array('type' => 'biginteger', 'null' => false, 'default' => '0'), $columns['org_id']);
        $this->assertSame(array('type' => 'biginteger', 'null' => true), $columns['1_event_id']);
        $this->assertSame(array('type' => 'biginteger', 'null' => false), $columns['value_id']);
        $this->assertSame(array('type' => 'biginteger', 'null' => true), $columns['lastpulledid']);
        $this->assertSame('string', $columns['request_id']['type']);
        $this->assertSame(array('type' => 'integer', 'unsigned' => true, 'null' => false), $columns['hits'], 'not an id: sign kept, width dropped');
    }

    public function testBooleanKeepsItsTypeWithoutWidth()
    {
        $targets = self::generator()->generate(array('t' => self::table(array(
            'flag' => array('type' => 'boolean', 'length' => 1, 'null' => false, 'default' => '0'),
        ))));
        $this->assertSame(array('type' => 'boolean', 'null' => false, 'default' => '0'), $targets['t']['columns']['flag']);
    }

    public function testEpochColumnsBecomeBigint()
    {
        $generator = self::generator(array('epoch' => array('t' => array('timestamp', 'expiration'))));
        $targets = $generator->generate(array('t' => self::table(array(
            'timestamp' => array('type' => 'integer', 'length' => 11, 'null' => false, 'default' => '0'),
            'expiration' => array('type' => 'integer', 'length' => 10, 'unsigned' => true, 'null' => false),
        ))));
        $this->assertSame(array('type' => 'biginteger', 'null' => false, 'default' => '0'), $targets['t']['columns']['timestamp']);
        $this->assertSame(array('type' => 'biginteger', 'null' => false), $targets['t']['columns']['expiration']);
        $this->assertSame(array(), $generator->warnings());
    }

    public function testEpochRuleRefusesANonInteger()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('t.created (epoch rule) is datetime, not an integer.');
        self::generator(array('epoch' => array('t' => array('created'))))->generate(array('t' => self::table(array(
            'created' => array('type' => 'datetime', 'null' => false),
        ))));
    }

    public function testUnlistedEpochNameIsReported()
    {
        $generator = self::generator();
        $generator->generate(array('t' => self::table(array(
            'last_seen_at' => array('type' => 'integer', 'length' => 11, 'null' => true),
            'version' => array('type' => 'integer', 'length' => 11, 'null' => true),
            'date_modified' => array('type' => 'biginteger', 'length' => 20, 'null' => true),
        ))));
        $this->assertSame(
            array('t.last_seen_at is a 32-bit integer named like an epoch, and is not in the epoch list.'),
            $generator->warnings()
        );
    }

    public function testCollationClasses()
    {
        $generator = self::generator(array(
            'ascii' => array('t' => array('uuid', 'hash')),
            'kept' => array('t' => array('object_type' => 'ascii_general_ci')),
        ));
        $targets = $generator->generate(array('t' => self::table(array(
            'uuid' => array('type' => 'string', 'length' => 40, 'null' => false),
            'hash' => array('type' => 'string', 'length' => 32, 'null' => true, 'collate' => 'utf8mb4_unicode_ci', 'charset' => 'utf8mb4'),
            'object_type' => array('type' => 'string', 'length' => 80, 'null' => false, 'collate' => 'ascii_general_ci', 'charset' => 'ascii'),
            'collection' => array('type' => 'string', 'length' => 40, 'null' => true, 'collate' => 'ascii_general_ci', 'charset' => 'ascii'),
            'name' => array('type' => 'string', 'length' => 255, 'null' => false, 'collate' => 'latin1_swedish_ci', 'charset' => 'latin1'),
            'value' => array('type' => 'text', 'null' => false),
            'info' => array('type' => 'text', 'null' => false, 'collate' => Collation::CI),
        ))));
        $columns = $targets['t']['columns'];
        $this->assertSame(Collation::ASCII, $columns['uuid']['collate'], 'listed: ascii whatever the table says');
        $this->assertSame(Collation::ASCII, $columns['hash']['collate'], 'listed: ascii whatever the column says');
        $this->assertArrayNotHasKey('charset', $columns['hash'], 'a token implies its charset');
        $this->assertSame(array('collate' => 'ascii_general_ci', 'charset' => 'ascii'), array_intersect_key($columns['object_type'], array_flip(array('collate', 'charset'))));
        $this->assertSame(Collation::CI, $columns['collection']['collate'], 'unlisted ascii *_ci: utf8mb4 CI');
        $this->assertSame(Collation::CI, $columns['name']['collate'], 'latin1 *_ci: CI');
        $this->assertSame(Collation::BIN, $columns['value']['collate'], 'no collation of its own: the table utf8mb3_bin is BIN');
        $this->assertSame(Collation::CI, $columns['info']['collate']);
        $this->assertSame(array(), $generator->warnings());
    }

    public function testUnlistedUuidNameIsReported()
    {
        $generator = self::generator();
        $generator->generate(array('t' => self::table(array(
            'org_uuid' => array('type' => 'string', 'length' => 40, 'null' => true),
            'payload_sha256' => array('type' => 'string', 'length' => 64, 'null' => true),
        ))));
        $this->assertSame(array(
            't.org_uuid is named like a uuid or hash, and is not in the ascii list.',
            't.payload_sha256 is named like a uuid or hash, and is not in the ascii list.',
        ), $generator->warnings());
    }

    public function testAnUnclassifiableCollationIsRefused()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('t.name: no class for the collation utf8mb4_0900_as_cs.');
        self::generator()->generate(array('t' => self::table(array(
            'name' => array('type' => 'string', 'length' => 10, 'null' => false, 'collate' => 'utf8mb4_0900_as_cs', 'charset' => 'utf8mb4'),
        ))));
    }

    public function testMediumtextRuleIsIdempotent()
    {
        $rules = array('mediumtext' => array('t' => array('rules', 'value')));
        $targets = self::generator($rules)->generate(array('t' => self::table(array(
            'rules' => array('type' => 'text', 'null' => true),
            'value' => array('type' => 'mediumtext', 'null' => false),
        ))));
        $this->assertSame('mediumtext', $targets['t']['columns']['rules']['type']);
        $this->assertSame('mediumtext', $targets['t']['columns']['value']['type']);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('t.rules (mediumtext rule) is string, not text.');
        self::generator($rules)->generate(array('t' => self::table(array(
            'rules' => array('type' => 'string', 'length' => 10, 'null' => true),
            'value' => array('type' => 'text', 'null' => false),
        ))));
    }

    public function testOverrideReplacesAnExpressionDefault()
    {
        $generator = self::generator(array(
            'epoch' => array('t' => array('created')),
            'overrides' => array(
                't' => array(
                    'created' => array('default' => '0'),
                    'created_at' => array('type' => 'datetime'),
                ),
            ),
        ));
        $targets = $generator->generate(array('t' => self::table(array(
            'created' => array('type' => 'integer', 'length' => 11, 'null' => false),
            'created_at' => array('type' => 'timestamp', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'),
        ), array(), 'utf8mb3_bin', array('created' => 'unix_timestamp()'))));
        $this->assertSame(array('type' => 'biginteger', 'null' => false, 'default' => '0'), $targets['t']['columns']['created']);
        $this->assertSame(array('type' => 'datetime', 'null' => false, 'default' => 'CURRENT_TIMESTAMP'), $targets['t']['columns']['created_at']);
        $this->assertContains("created: integer NOT NULL -> biginteger NOT NULL DEFAULT '0' (epoch, override)", $generator->notes()['t']);
    }

    public function testALeftoverExpressionDefaultIsRefused()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('t.created: expression default unix_timestamp() has no rule.');
        self::generator()->generate(array('t' => self::table(array(
            'created' => array('type' => 'integer', 'length' => 11, 'null' => false),
        ), array(), 'utf8mb3_bin', array('created' => 'unix_timestamp()'))));
    }

    public function testStaleListsAreRefusedAllAtOnce()
    {
        try {
            self::generator(array(
                'epoch' => array('t' => array('gone')),
                'ascii' => array('missing' => array('uuid')),
                'overrides' => array('t' => array('also_gone' => array('default' => '0'))),
                'additions' => array('nowhere' => array('i' => array('column' => array('a')))),
            ))->generate(array('t' => self::table(array('id' => self::id()))));
            $this->fail('No exception');
        } catch (RuntimeException $e) {
            $this->assertStringContainsString('t.gone (epoch rule) is not in the reference.', $e->getMessage());
            $this->assertStringContainsString('missing.uuid (ascii rule) is not in the reference.', $e->getMessage());
            $this->assertStringContainsString('t.also_gone (override rule) is not in the reference.', $e->getMessage());
            $this->assertStringContainsString('Index rules name the table nowhere, which is not in the reference.', $e->getMessage());
        }
    }

    public function testExcludedTablesAreLeftOutAndTablesSortedByName()
    {
        $targets = self::generator(array('excluded' => array('logs')))->generate(array(
            'b_c' => self::table(array('id' => self::id())),
            'logs' => self::table(array('id' => self::id())),
            'bc' => self::table(array('id' => self::id())),
        ));
        $this->assertSame(array('b_c', 'bc'), array_keys($targets));
    }

    public function testOptionsAndColumnKeyOrder()
    {
        $targets = self::generator()->generate(array('t' => self::table(array(
            'name' => array('null' => true, 'collate' => 'utf8mb3_bin', 'charset' => 'utf8mb3', 'length' => 7, 'type' => 'string', 'default' => ''),
        ))));
        $this->assertSame(
            array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
            $targets['t']['options']
        );
        $this->assertSame(array('type', 'length', 'null', 'default', 'collate'), array_keys($targets['t']['columns']['name']));
    }

    // ------------------------------------------------------------- indexes

    public function testVarcharPrefixDroppedTextPrefixKept()
    {
        $generator = self::generator();
        $targets = $generator->generate(array('t' => self::table(
            array(
                'url' => array('type' => 'string', 'length' => 255, 'null' => false),
                'info' => array('type' => 'text', 'null' => false),
            ),
            array(
                'url' => array('column' => array('url'), 'length' => array('url' => 191)),
                'info' => array('column' => array('info'), 'length' => array('info' => 255)),
            )
        )));
        $this->assertSame(array('column' => array('url')), $targets['t']['indexes']['url']);
        $this->assertSame(array('column' => array('info'), 'length' => array('info' => 255)), $targets['t']['indexes']['info']);
        $this->assertContains('index url: prefix url(191) dropped, the varchar is indexed whole', $generator->notes()['t']);
    }

    public function testAdditionsAndRetirements()
    {
        $generator = self::generator(array(
            'additions' => array('t' => array(
                'idx_acl' => array('column' => array('event_id', 'distribution')),
                'uuid' => array('column' => array('uuid'), 'unique' => true),
            )),
            'retired' => array('t' => array('event_id', 'distribution', 'idx_pack_only')),
        ));
        $targets = $generator->generate(array('t' => self::table(
            array(
                'id' => self::id(),
                'event_id' => array('type' => 'integer', 'length' => 11, 'null' => false),
                'distribution' => array('type' => 'tinyinteger', 'length' => 4, 'null' => false),
                'uuid' => array('type' => 'string', 'length' => 40, 'null' => false),
            ),
            array(
                'event_id' => array('column' => array('event_id')),
                'distribution' => array('column' => array('distribution')),
                'uuid' => array('column' => array('uuid'), 'unique' => true),
            )
        )));
        $this->assertSame(array('idx_acl', 'uuid'), array_keys($targets['t']['indexes']));
        $this->assertSame(array('distribution', 'event_id', 'idx_pack_only'), $targets['t']['retired']);
        $notes = $generator->notes()['t'];
        $this->assertContains('index idx_acl (event_id, distribution) added', $notes);
        $this->assertContains('index event_id (event_id) retired; covered by idx_acl', $notes);
        $this->assertContains('index distribution (distribution) retired; no target index starts with its columns', $notes);
        $this->assertContains('index idx_pack_only retired; not in the reference, dropped where an instance has it', $notes);
    }

    public function testAnAdditionThatDisagreesWithTheReferenceIsRefused()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('t: index idx_acl is in the reference with another definition.');
        self::generator(array('additions' => array('t' => array('idx_acl' => array('column' => array('a', 'b'))))))->generate(array(
            't' => self::table(
                array('a' => array('type' => 'integer', 'null' => false), 'b' => array('type' => 'integer', 'null' => false)),
                array('idx_acl' => array('column' => array('b', 'a')))
            ),
        ));
    }

    public function testAnAdditionOverAMissingColumnIsRefused()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('t: index idx_x covers nope, which is not a column.');
        self::generator(array('additions' => array('t' => array('idx_x' => array('column' => array('nope'))))))->generate(array(
            't' => self::table(array('id' => self::id())),
        ));
    }

    public function testPostgresqlIndexForms()
    {
        $targets = self::generator(array(
            'pgsqlReplaced' => array('t' => array('value' => array(
                'name' => 'idx_t_value',
                'sql' => 'CREATE INDEX %1$s ON %2$s (lower(left("value", 128)));',
                'reads' => 'lower(',
            ))),
            'pgsqlOnly' => array('t' => array('idx_t_name_lower' => 'CREATE UNIQUE INDEX %1$s ON %2$s (lower("name"));')),
        ))->generate(array('t' => self::table(
            array(
                'value' => array('type' => 'text', 'null' => false),
                'name' => array('type' => 'string', 'length' => 255, 'null' => false),
            ),
            array('value' => array('column' => array('value'), 'length' => array('value' => 128)))
        )));
        $this->assertSame(array(
            'idx_t_name_lower' => array('mysql' => false, 'pgsql' => array('sql' => 'CREATE UNIQUE INDEX %1$s ON %2$s (lower("name"));')),
            'value' => array(
                'column' => array('value'),
                'length' => array('value' => 128),
                'pgsql' => array('name' => 'idx_t_value', 'sql' => 'CREATE INDEX %1$s ON %2$s (lower(left("value", 128)));'),
            ),
        ), $targets['t']['indexes']);
    }

    public function testAReplacementForAMissingIndexIsRefused()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('t: PostgreSQL replaces the index value, which the target does not have.');
        self::generator(array('pgsqlReplaced' => array('t' => array('value' => array('name' => 'x', 'sql' => 'y')))))
            ->generate(array('t' => self::table(array('id' => self::id()))));
    }

    public function testCoveringIndex()
    {
        $indexes = array(
            'a' => array('column' => array('a')),
            'a_dup' => array('column' => array('a')),
            'ab' => array('column' => array('a', 'b')),
            'ba' => array('column' => array('b', 'a')),
            'u_c' => array('column' => array('c'), 'unique' => true),
            'c' => array('column' => array('c')),
            'p' => array('column' => array('p'), 'length' => array('p' => 64)),
            'p_narrow' => array('column' => array('p'), 'length' => array('p' => 16)),
            'ft' => array('column' => array('b'), 'fulltext' => true),
            'pg_only' => array('mysql' => false, 'pgsql' => array('sql' => 'x')),
        );
        $this->assertSame('ab', SchemaTargetGenerator::coveringIndex($indexes['a'], $indexes, 'a'));
        $this->assertSame('a', SchemaTargetGenerator::coveringIndex($indexes['a_dup'], $indexes, 'a_dup'));
        $twins = array('x' => array('column' => array('x')), 'y' => array('column' => array('x')));
        $this->assertNull(SchemaTargetGenerator::coveringIndex($twins['x'], $twins, 'x'), 'of two twins, only the later name is reported');
        $this->assertSame('x', SchemaTargetGenerator::coveringIndex($twins['y'], $twins, 'y'));
        $this->assertSame('x', SchemaTargetGenerator::coveringIndex($twins['y'], $twins), 'a retired index is covered by its twin');
        $this->assertNull(SchemaTargetGenerator::coveringIndex($indexes['u_c'], $indexes, 'u_c'), 'a unique key is never redundant');
        $this->assertSame('u_c', SchemaTargetGenerator::coveringIndex($indexes['c'], $indexes, 'c'));
        $this->assertNull(SchemaTargetGenerator::coveringIndex($indexes['p'], $indexes, 'p'), 'a shorter prefix does not cover');
        $this->assertSame('p', SchemaTargetGenerator::coveringIndex($indexes['p_narrow'], $indexes, 'p_narrow'));
        $this->assertSame('ba', SchemaTargetGenerator::coveringIndex(array('column' => array('b')), $indexes), 'fulltext never covers');
        $this->assertNull(SchemaTargetGenerator::coveringIndex($indexes['ft'], $indexes, 'ft'));
        $this->assertNull(SchemaTargetGenerator::coveringIndex($indexes['pg_only'], $indexes, 'pg_only'));
    }

    public function testRedundantTargetIndexIsReported()
    {
        $generator = self::generator();
        $generator->generate(array('t' => self::table(
            array('a' => array('type' => 'integer', 'null' => false), 'b' => array('type' => 'integer', 'null' => false)),
            array('a' => array('column' => array('a')), 'ab' => array('column' => array('a', 'b')))
        )));
        $this->assertSame(array('t: index a (a) is covered by ab (a, b).'), $generator->warnings());
    }

    // --------------------------------------------------------- key lengths

    public function testKeyBytes()
    {
        $columns = array(
            'uuid' => array('type' => 'string', 'length' => 40, 'collate' => Collation::ASCII),
            'kind' => array('type' => 'string', 'length' => 80, 'collate' => 'ascii_general_ci', 'charset' => 'ascii'),
            'name' => array('type' => 'string', 'length' => 255, 'collate' => Collation::CI),
            'info' => array('type' => 'text', 'collate' => Collation::CI),
            'hash' => array('type' => 'varbinary', 'length' => 32),
            'id' => array('type' => 'biginteger'),
            'flag' => array('type' => 'boolean'),
        );
        $mysql = AbstractGrammar::FLAVOUR_MYSQL;
        $pgsql = AbstractGrammar::FLAVOUR_PGSQL;
        $this->assertSame(40 + 80 + 8 + 1, SchemaTargetGenerator::keyBytes($columns, array('column' => array('uuid', 'kind', 'id', 'flag')), $mysql));
        $this->assertSame(160 + 320 + 8 + 1, SchemaTargetGenerator::keyBytes($columns, array('column' => array('uuid', 'kind', 'id', 'flag')), $pgsql));
        $this->assertSame(1020 + 32, SchemaTargetGenerator::keyBytes($columns, array('column' => array('name', 'hash')), $mysql));
        $this->assertSame(1020, SchemaTargetGenerator::keyBytes($columns, array('column' => array('info'), 'length' => array('info' => 255)), $mysql));
        $this->assertNull(SchemaTargetGenerator::keyBytes($columns, array('column' => array('info'), 'length' => array('info' => 255)), $pgsql));
    }

    public function testAKeyOverTheMysqlLimitIsRefused()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('t: index wide is 3080 bytes, over the 3072-byte key limit.');
        self::generator()->generate(array('t' => self::table(
            array(
                'a' => array('type' => 'string', 'length' => 768, 'null' => false),
                'b' => array('type' => 'biginteger', 'null' => false),
            ),
            array('wide' => array('column' => array('a', 'b')))
        )));
    }

    public function testAKeyOverThePostgresqlBtreeLimitIsRefused()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('t: index url can reach 2800 bytes on PostgreSQL, over its 2704-byte btree entry limit.');
        self::generator()->generate(array('t' => self::table(
            array('url' => array('type' => 'string', 'length' => 700, 'null' => false, 'collate' => 'ascii_general_ci', 'charset' => 'ascii')),
            array('url' => array('column' => array('url'))),
            'ascii_general_ci'
        )));
    }

    public function testUniqueTextPrefixIsUnboundedOnPostgresql()
    {
        $generator = self::generator();
        $generator->generate(array('t' => self::table(
            array(
                'value' => array('type' => 'text', 'null' => false),
                'info' => array('type' => 'text', 'null' => false),
            ),
            array(
                'value' => array('column' => array('value'), 'length' => array('value' => 191), 'unique' => true),
                'info' => array('column' => array('info'), 'length' => array('info' => 255)),
            )
        )));
        $this->assertSame(array(
            't: index value (value(191)) is a full-column btree on PostgreSQL over unbounded text; a value over 2704 bytes cannot be stored.',
        ), $generator->warnings());
        $lengths = $generator->keyLengths();
        $this->assertSame(array('mysql' => 1020, 'pgsql' => false), $lengths['t.info'], 'a hash index on PostgreSQL');
        $this->assertSame(array('mysql' => 764, 'pgsql' => null), $lengths['t.value']);
    }

    // -------------------------------------------------------------- export

    public function testExportRoundTrips()
    {
        $targets = self::generator(array(
            'ascii' => array('t' => array('uuid')),
            'pgsqlOnly' => array('t' => array('idx_lower' => 'CREATE UNIQUE INDEX %1$s ON %2$s (lower("name"));')),
            'retired' => array('t' => array('old')),
        ))->generate(array('t' => self::table(
            array(
                'id' => self::id(),
                'uuid' => array('type' => 'string', 'length' => 40, 'null' => false),
                'name' => array('type' => 'string', 'length' => 255, 'null' => true, 'default' => "it's \\ here", 'collate' => 'utf8mb4_unicode_ci', 'charset' => 'utf8mb4'),
            ),
            array('uuid' => array('column' => array('uuid'), 'unique' => true))
        )));
        $php = SchemaTargetGenerator::exportAll($targets);
        $this->assertStringContainsString("'collate' => Collation::ASCII", $php);
        $this->assertStringNotContainsString('<ASCII>', $php);
        $this->assertSame($targets, eval('?>' . $php));
    }

    public function testExportTargetLayout()
    {
        $target = array(
            'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),
            'columns' => array(
                'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),
            ),
            'indexes' => array(),
            'retired' => array(),
        );
        $this->assertSame(
            "array(\n"
            . "        'options' => array('engine' => 'InnoDB', 'row_format' => 'DYNAMIC', 'collate' => Collation::CI),\n"
            . "        'columns' => array(\n"
            . "            'id' => array('type' => 'biginteger', 'null' => false, 'key' => 'primary'),\n"
            . "        ),\n"
            . "        'indexes' => array(),\n"
            . "        'retired' => array(),\n"
            . "    )",
            SchemaTargetGenerator::exportTarget($target, 4)
        );
    }

    public function testExportWrapsLongEntries()
    {
        $long = array('column' => array('aaaaaaaaaa', 'bbbbbbbbbb', 'cccccccccc', 'dddddddddd', 'eeeeeeeeee', 'ffffffffff', 'gggggggggg'));
        $out = SchemaTargetGenerator::export($long, 8, 30);
        $this->assertStringContainsString("\n", $out);
        $this->assertSame($long, eval('return ' . $out . ';'));
        foreach (explode("\n", $out) as $line) {
            $this->assertLessThanOrEqual(SchemaTargetGenerator::EXPORT_WIDTH, strlen($line) + 8);
        }
    }

    // ---------------------------------------------------------- the whole

    public function testATargetIsAFixedPoint()
    {
        $rules = array(
            'epoch' => array('t' => array('timestamp')),
            'ascii' => array('t' => array('uuid')),
            'mediumtext' => array('t' => array('rules')),
            'additions' => array('t' => array('idx_ts' => array('column' => array('timestamp', 'id')))),
            'retired' => array('t' => array('timestamp')),
        );
        $first = self::generator($rules)->generate(array('t' => self::table(
            array(
                'id' => self::id(),
                'timestamp' => array('type' => 'integer', 'length' => 11, 'null' => false, 'default' => '0'),
                'uuid' => array('type' => 'string', 'length' => 40, 'null' => false),
                'rules' => array('type' => 'text', 'null' => true),
                'name' => array('type' => 'string', 'length' => 191, 'null' => false, 'collate' => 'utf8mb4_general_ci', 'charset' => 'utf8mb4'),
            ),
            array(
                'timestamp' => array('column' => array('timestamp')),
                'name' => array('column' => array('name'), 'length' => array('name' => 100)),
            )
        )));

        // What reading a database created from the target back gives.
        $loaded = $first['t'];
        $loaded['primary'] = 'id';
        $loaded['options'] = array('engine' => 'InnoDB', 'collate' => Collation::CI);
        $loaded['expressionDefaults'] = array();
        foreach ($loaded['indexes'] as $name => $index) {
            $loaded['indexes'][$name] = array('name' => $name, 'unique' => !empty($index['unique'])) + $index;
        }
        unset($loaded['retired']);

        $generator = self::generator($rules);
        $this->assertSame($first, $generator->generate(array('t' => $loaded)));
        $this->assertSame(array('index timestamp retired; not in the reference, dropped where an instance has it'), $generator->notes()['t']);
    }

    public function testReportSections()
    {
        $generator = self::generator(array('excluded' => array('logs'), 'ascii' => array('t' => array('uuid'))));
        $targets = $generator->generate(array(
            't' => self::table(
                array(
                    'id' => self::id(),
                    'uuid' => array('type' => 'string', 'length' => 40, 'null' => false),
                    'org_uuid' => array('type' => 'string', 'length' => 40, 'null' => false),
                ),
                array('uuid' => array('column' => array('uuid'), 'unique' => true))
            ),
            'logs' => self::table(array('id' => self::id())),
        ));
        $report = $generator->report($targets, 'ref (10.11.14-MariaDB)');
        $this->assertStringContainsString('1 tables from ref (10.11.14-MariaDB); not converged: logs.', $report);
        $this->assertStringContainsString("## Warnings (1)\n\n- t.org_uuid is named like a uuid or hash", $report);
        $this->assertStringContainsString('- t.uuid: MySQL 40, PostgreSQL 160', $report);
        $this->assertStringContainsString("## ascii_bin columns (1)\n\nt.uuid", $report);
        $this->assertStringContainsString("### t\n\n- id: integer NOT NULL -> biginteger NOT NULL (id)", $report);
    }

    public function testUnknownRuleIsRefused()
    {
        $this->expectException(InvalidArgumentException::class);
        new SchemaTargetGenerator(array('epochs' => array()));
    }

    /**
     * The shipped lists: every entry is table => list of column names, no
     * table is both converged and excluded, and the additions are indexes
     * the generator can read.
     */
    public function testShippedListsAreWellFormed()
    {
        $lists = array(
            SchemaTargetGenerator::HIDDEN_ID_COLUMNS, SchemaTargetGenerator::EPOCH_COLUMNS,
            SchemaTargetGenerator::MEDIUMTEXT_COLUMNS, SchemaTargetGenerator::ASCII_COLUMNS,
            SchemaTargetGenerator::RETIRED_INDEXES,
        );
        foreach ($lists as $list) {
            foreach ($list as $table => $columns) {
                $this->assertIsString($table);
                $this->assertSame(array_values(array_unique($columns)), $columns, $table);
                $this->assertNotContains($table, SchemaTargetGenerator::EXCLUDED_TABLES);
            }
        }
        $ascii = 0;
        foreach (SchemaTargetGenerator::ASCII_COLUMNS as $columns) {
            $ascii += count($columns);
        }
        $this->assertSame(76, $ascii);
        $epochs = 0;
        foreach (SchemaTargetGenerator::EPOCH_COLUMNS as $columns) {
            $epochs += count($columns);
        }
        $this->assertSame(35, $epochs);
        foreach (SchemaTargetGenerator::INDEX_ADDITIONS as $table => $indexes) {
            foreach ($indexes as $name => $index) {
                $this->assertSame(array('column'), array_values(array_diff(array_keys($index), array('length'))), "$table.$name");
                $this->assertArrayNotHasKey($name, array_flip(isset(SchemaTargetGenerator::RETIRED_INDEXES[$table]) ? SchemaTargetGenerator::RETIRED_INDEXES[$table] : array()), "$table.$name is added and retired");
            }
        }
    }
}
