<?php
/**
 * The value_search restSearch filter. An attribute matches when its value1 or
 * value2 holds the search text from the start of a word, ignoring case but not
 * accents; the text is literal. Selective texts are read ahead through the
 * FULLTEXT index; broad ones, and any text in a bounded find, are checked
 * inside the statement without the index, with the same result. The
 * attribute, event and object scopes take OR, AND and NOT terms.
 *
 * InnoDB's FULLTEXT index only sees committed rows, so the fixture values are
 * interned before the test's transaction and deleted by id after it; the
 * attributes are saved inside the transaction, which is rolled back. Every
 * value holds a random token no stored value holds.
 *
 * Skipped unless ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real
 * application, so it must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueSearchDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueSearchDbTest extends TestCase
{
    private static $booted = false;

    /** @var MispAttribute */
    private $attribute;

    /** @var Event */
    private $event;

    /** @var AttributeValue */
    private $values;

    /** @var DboSource */
    private $db;

    /** @var array */
    private $user;

    /** @var string */
    private $t;

    /** @var string made of words too short for the index */
    private $short;

    /** @var string */
    private $md5;

    /** @var int[] */
    private $events;

    /** @var array name => attribute id */
    private $ids = [];

    /** @var int[] dictionary ids interned for the test */
    private $interned = [];

    /** @var bool */
    private $cachedMethods;

    /** @var bool */
    private $fullDebug;

    /** @var mixed */
    private $currentUserId;

    protected function setUp(): void
    {
        if (!getenv('ATTRIBUTE_VALUE_DB_TESTS')) {
            $this->markTestSkipped('Needs the database, see the file header.');
        }
        if (!self::$booted) {
            if (class_exists('App', false)) {
                $this->markTestSkipped('Needs its own process: run this file alone.');
            }
            require_once __DIR__ . '/OracleBootstrap.php';
            require_once __DIR__ . '/AttributeValueTextSupport.php';
            App::uses('ClassRegistry', 'Utility');
            App::uses('AttributeValue', 'Model');
            App::uses('CakeText', 'Utility');
            App::uses('RedisTool', 'Tools');
            AttributeValue::$strictConditions = true;
            self::$booted = true;
        }
        $this->attribute = ClassRegistry::init('MispAttribute');
        $this->event = $this->attribute->Event;
        $this->values = $this->attribute->loadAttributeValue();
        $this->db = $this->attribute->getDataSource();
        if (!($this->db instanceof Mysql)) {
            // Skipped before the fixture exists: nothing for tearDown to clean up
            $this->db = null;
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        $this->cachedMethods = $this->db->cacheMethods;
        $this->fullDebug = $this->db->fullDebug;
        $this->user = ClassRegistry::init('User')->getAuthUser(1);
        $this->currentUserId = Configure::read('CurrentUserId');
        Configure::write('CurrentUserId', $this->user['id']);
        $this->t = 'vs' . bin2hex(random_bytes(5));
        $this->short = implode('.', str_split(bin2hex(random_bytes(4)), 2));
        $this->md5 = bin2hex(random_bytes(16));
        $this->events = array_map('intval', $this->event->find('column', [
            'order' => ['Event.id' => 'ASC'],
            'fields' => ['Event.id'],
            'limit' => 3,
        ]));
        $fixture = $this->fixture();
        $this->intern($fixture);
        $this->db->begin();
        $this->add($fixture);
        $this->db->fullDebug = true;
    }

    protected function tearDown(): void
    {
        if (!$this->db) {
            return;
        }
        Configure::write('CurrentUserId', $this->currentUserId);
        $this->db->cacheMethods = $this->cachedMethods;
        $this->db->fullDebug = $this->fullDebug;
        foreach ($this->attributeModels() as $model) {
            $model->schema(true);
        }
        $this->db->rollback();
        $this->resetStopwordCheck();
        if (!empty($this->interned)) {
            $ids = implode(', ', $this->interned);
            $held = $this->exec("SELECT 1 FROM attributes WHERE value1_id IN ($ids) OR value2_id IN ($ids) LIMIT 1");
            $this->assertEmpty($held, 'An interned fixture value is still referenced.');
            $this->exec("DELETE FROM value_ip_ranges WHERE value_id IN ($ids)");
            $this->exec("DELETE FROM attribute_values WHERE id IN ($ids)");
        }
    }

    private function exec($sql)
    {
        $statement = $this->db->rawQuery($sql);
        if (!($statement instanceof PDOStatement)) {
            return [];
        }
        $rows = $statement->columnCount() > 0 ? $statement->fetchAll(PDO::FETCH_ASSOC) : [];
        $statement->closeCursor();
        return $rows;
    }

    /**
     * @return array name => [event index, type, value]
     */
    private function fixture()
    {
        $t = $this->t;
        return [
            'a_dom' => [0, 'text', "mail.$t.example"],
            'a_url' => [0, 'text', "https://www.$t.com/wp-admin/x.php"],
            'a_mid' => [0, 'text', "x$t.example"],
            'a_comp' => [0, 'domain|ip', "$t.example|192.0.2.77"],
            'a_hash' => [0, 'filename|md5', "$t.exe|{$this->md5}"],
            'b_upper' => [1, 'text', strtoupper("mail.$t.example")],
            'b_accent' => [1, 'text', "$t café"],
            'b_pct' => [1, 'text', "$t 50%off"],
            'b_short' => [1, 'text', "{$this->short}.ex"],
            'c_other' => [2, 'text', 'unrelated ' . bin2hex(random_bytes(6))],
        ];
    }

    /**
     * Committed, so that the FULLTEXT index holds the values.
     *
     * @param array $fixture
     * @return void
     */
    private function intern(array $fixture)
    {
        $parts = [];
        foreach ($fixture as $spec) {
            foreach (explode('|', $spec[2]) as $part) {
                $parts[] = $part;
            }
        }
        $missing = array_values(array_diff($parts, array_keys($this->values->idsOf($parts))));
        $this->assertCount(count(array_unique($parts)), $missing, 'A fixture value is already stored.');
        $this->interned = array_values(array_map('intval', $this->values->internMany($missing)));
    }

    /**
     * Attributes saved without correlating, inside the transaction.
     *
     * @param array $fixture
     * @return void
     */
    private function add(array $fixture)
    {
        foreach ($fixture as $name => $spec) {
            list($event, $type, $value) = $spec;
            $this->attribute->create();
            $saved = $this->attribute->save(['Attribute' => [
                'event_id' => $this->events[$event],
                'category' => $this->attribute->typeDefinitions[$type]['default_category'],
                'type' => $type,
                'value' => $value,
                'distribution' => 5,
                'to_ids' => 0,
                'disable_correlation' => 1,
            ]]);
            $this->assertNotFalse($saved, $name . json_encode($this->attribute->validationErrors));
            $this->ids[$name] = (int)$this->attribute->id;
        }
        $ids = implode(', ', $this->ids);
        foreach ($this->exec("SELECT value1_id, value2_id FROM attributes WHERE id IN ($ids)") as $row) {
            foreach ($row as $id) {
                if ($id !== null) {
                    $this->assertContains((int)$id, $this->interned, 'A save stored a spelling the test did not intern.');
                }
            }
        }
        AttributeValueTextSupport::diverge($this->db, 'attributes', sprintf(
            "UPDATE attributes SET value1 = 'column-x', value2 = IF(value2 = '', '', 'column-x') WHERE id IN (%s)",
            $ids
        ));
        $this->hideTextColumns();
    }

    private function attributeModels()
    {
        $models = [spl_object_id($this->attribute) => $this->attribute];
        foreach (ClassRegistry::keys() as $key) {
            $object = ClassRegistry::getObject($key);
            if ($object instanceof MispAttribute) {
                $models[spl_object_id($object)] = $object;
            }
        }
        return $models;
    }

    private function hideTextColumns()
    {
        $this->attribute->Event->Object->Attribute;
        $property = new ReflectionProperty('Model', '_schema');
        foreach ($this->attributeModels() as $model) {
            $schema = $model->schema();
            unset($schema['value1'], $schema['value2']);
            $property->setValue($model, $schema);
        }
        $this->db->cacheMethods = false;
    }

    private function resetStopwordCheck()
    {
        $property = new ReflectionProperty('AttributeValue', 'holdsStopwords');
        $property->setAccessible(true);
        $property->setValue($this->values, null);
        RedisTool::init()->del(AttributeValue::STOPWORD_CACHE_KEY);
    }

    private function ids(...$names)
    {
        $ids = [];
        foreach ($names as $name) {
            $ids[] = $this->ids[$name];
        }
        sort($ids);
        return $ids;
    }

    private function except(...$names)
    {
        return $this->ids(...array_diff(array_keys($this->ids), $names));
    }

    private function select(array $conditions)
    {
        $ids = array_map('intval', $this->attribute->find('column', [
            'conditions' => ['AND' => [['Attribute.id' => array_values($this->ids)], $conditions]],
            'fields' => ['Attribute.id'],
        ]));
        sort($ids);
        return $ids;
    }

    private function filter($value)
    {
        $params = ['value_search' => $value];
        return $this->event->set_filter_value_search($params, [], ['filter' => 'value_search', 'context' => 'Attribute']);
    }

    private function statements($pattern)
    {
        $out = [];
        foreach ($this->db->getLog(false, false)['log'] as $entry) {
            if (preg_match($pattern, $entry['query'])) {
                $out[] = $entry['query'];
            }
        }
        return $out;
    }

    /**
     * The dictionary reads ahead of a find.
     *
     * @return string[]
     */
    private function resolves()
    {
        return $this->statements('/^(?:\/\*.*?\*\/ )?SELECT `id` FROM `attribute_values`/');
    }

    private function clearLog()
    {
        $this->db->getLog(false, true);
    }

    private function eventIds(array $params)
    {
        $ids = array_map('intval', $this->event->filterEventIds($this->user, $params));
        sort($ids);
        return $ids;
    }

    /**
     * Objects 0 and 2 in the first event, 1 in the second; object 2 has no
     * attributes.
     *
     * @return int[]
     */
    private function createObjects()
    {
        list($first, $second) = $this->events;
        $objects = [];
        foreach ([$first, $second, $first] as $eventId) {
            $this->exec(sprintf(
                "INSERT INTO objects (name, `meta-category`, template_uuid, template_version, event_id, uuid, timestamp, distribution, comment, deleted) VALUES ('file', 'file', '%s', 1, %d, '%s', %d, 5, '', 0)",
                CakeText::uuid(),
                $eventId,
                CakeText::uuid(),
                time()
            ));
            $objects[] = (int)$this->exec('SELECT LAST_INSERT_ID() AS id')[0]['id'];
        }
        $this->exec(sprintf('UPDATE attributes SET object_id = %d WHERE id = %d', $objects[0], $this->ids['a_mid']));
        $this->exec(sprintf('UPDATE attributes SET object_id = %d WHERE id = %d', $objects[1], $this->ids['b_pct']));
        return $objects;
    }

    private function objectIds(array $params, array $objects)
    {
        $object = $this->event->Object;
        $conditions = $object->buildFilterConditions($params);
        $found = $object->fetchObjects($this->user, [
            'conditions' => ['AND' => [['Object.id' => $objects], $conditions]],
            'metadata' => 1,
        ]);
        $ids = array_map('intval', array_column(array_column($found, 'Object'), 'id'));
        sort($ids);
        return $ids;
    }

    public function testATextMatchesWhereItStartsAWord()
    {
        $t = $this->t;
        $every = ['a_dom', 'a_url', 'a_comp', 'a_hash', 'b_upper', 'b_accent', 'b_pct'];
        $cases = [
            ["$t.example", ['a_dom', 'a_comp', 'b_upper']],
            [strtoupper("$t.EXAMPLE"), ['a_dom', 'a_comp', 'b_upper']],
            ["x$t", ['a_mid']],
            [$t, $every],
            // A word's start, not its middle
            [substr($t, 0, 7), $every],
            [substr($t, 2), []],
            ["www.$t.com", ['a_url']],
            [".$t.com/wp", ['a_url']],
            // Punctuation first: no word start needed
            ['/wp-admin/x.php', ['a_url']],
            ["$t.exe", ['a_hash']],
            // value2 on its own, from the start of the hash only
            [substr($this->md5, 0, 12), ['a_hash']],
            [substr($this->md5, 4, 12), []],
            // Each part on its own
            ["$t.example|192.0.2.77", []],
        ];
        foreach ($cases as $case) {
            list($text, $expected) = $case;
            $this->clearLog();
            $ahead = $this->values->searchCondition([$text], 'Attribute');
            $resolve = $this->resolves();
            $this->assertCount(1, $resolve, $text);
            $this->assertStringContainsString('MATCH(`value`) AGAINST(', $resolve[0], $text);
            $this->clearLog();
            $this->assertSame($this->ids(...$expected), $this->select($ahead), $text);
            // Read ahead: the find names the ids
            $find = $this->statements('/`attributes` AS `Attribute`/');
            $this->assertCount(1, $find, $text);
            $this->assertStringNotContainsString('attribute_values', $find[0], $text);

            $this->clearLog();
            $bounded = $this->values->searchCondition([$text], 'Attribute', false, true);
            $this->assertSame([], $this->statements('/attribute_values/'), $text);
            $this->assertSame($this->ids(...$expected), $this->select($bounded), "$text (bounded)");
            $find = $this->statements('/`attributes` AS `Attribute`/');
            $this->assertStringContainsString('IN (SELECT `id` FROM `attribute_values` WHERE `value` LIKE', $find[0], $text);
            $this->assertStringNotContainsString('MATCH(', $find[0], $text);
        }
    }

    public function testTheTextIsLiteralAndAccentsCount()
    {
        $t = $this->t;
        $cases = [
            ["$t café", ['b_accent']],
            ["$t CAFÉ", ['b_accent']],
            ["$t cafe", []],
            ["$t 50%", ['b_pct']],
            // Neither % nor _ is a wildcard
            ["$t 5%", []],
            ["$t 50_off", []],
        ];
        foreach ($cases as $case) {
            list($text, $expected) = $case;
            $this->assertSame($this->ids(...$expected), $this->select($this->values->searchCondition([$text], 'Attribute')), $text);
            $this->assertSame($this->ids(...$expected), $this->select($this->values->searchCondition([$text], 'Attribute', false, true)), "$text (bounded)");
        }
    }

    public function testATextWithoutAWordTheIndexHoldsScansTheDictionary()
    {
        $this->clearLog();
        $this->assertSame($this->ids('b_short'), $this->select($this->values->searchCondition([$this->short], 'Attribute')));
        $resolve = $this->resolves();
        $this->assertCount(1, $resolve);
        $this->assertStringNotContainsString('MATCH(', $resolve[0]);
    }

    public function testAnOverflowReadsTheDictionaryInsideTheStatement()
    {
        $t = $this->t;
        $cases = [
            [[$t], false],
            [["$t.example", "x$t"], false],
            [[$t], true],
            [["$t.example", substr($this->md5, 0, 12)], true],
        ];
        foreach ($cases as $case) {
            list($texts, $not) = $case;
            $expected = $this->select($this->values->searchCondition($texts, 'Attribute', $not));
            $this->assertNotEmpty($expected);
            $this->clearLog();
            $this->assertSame($expected, $this->select($this->values->searchCondition($texts, 'Attribute', $not, false, 1)), json_encode($case));
            $find = $this->statements('/`attributes` AS `Attribute`/');
            $this->assertCount(1, $find);
            $this->assertStringContainsString(
                sprintf('`Attribute`.`value2_id` %s (SELECT `id` FROM `attribute_values` WHERE `value` LIKE', $not ? 'NOT IN' : 'IN'),
                $find[0]
            );
            // The index search would run whole however few rows the find keeps
            $this->assertStringNotContainsString('MATCH(', $find[0]);
        }
    }

    public function testStopwordsTheIndexMayLackAreLeftToTheCheck()
    {
        $t = $this->t;
        $redis = RedisTool::init();
        $this->resetStopwordCheck();

        $this->clearLog();
        $this->assertSame($this->ids('a_url'), $this->select($this->values->searchCondition(["www.$t.com"], 'Attribute')));
        $probe = $this->statements("/AGAINST\('the with from this' IN BOOLEAN MODE\) LIMIT 1/");
        $this->assertCount(1, $probe);
        $this->assertSame('1', $redis->get(AttributeValue::STOPWORD_CACHE_KEY), 'The index holds stopwords.');
        $ttl = $redis->ttl(AttributeValue::STOPWORD_CACHE_KEY);
        $this->assertGreaterThan(0, $ttl);
        $this->assertLessThanOrEqual(AttributeValue::STOPWORD_CACHE_SECONDS, $ttl);
        $this->assertCount(1, $this->statements("/AGAINST\('\+$t \+www \+com\*' IN BOOLEAN MODE\)/"));

        // Answered from the model, then from Redis
        $this->clearLog();
        $this->values->searchCondition(["$t.com"], 'Attribute');
        $this->assertSame([], $this->statements('/the with from this/'));

        $this->resetStopwordCheck();
        $redis->set(AttributeValue::STOPWORD_CACHE_KEY, '0');
        $this->clearLog();
        $this->assertSame($this->ids('a_url'), $this->select($this->values->searchCondition(["www.$t.com"], 'Attribute')));
        $this->assertSame([], $this->statements('/the with from this/'));
        $this->assertCount(1, $this->statements("/AGAINST\('\+$t' IN BOOLEAN MODE\) AND `value` LIKE/"));
    }

    public function testTheAttributeScopeTakesOrAndAndNot()
    {
        $t = $this->t;
        $hash = substr($this->md5, 0, 12);
        $cases = [
            [["x$t", "$t.exe"], ['a_mid', 'a_hash']],
            ["x$t&&$t.exe", ['a_mid', 'a_hash']],
            [['AND' => [$t, "$t.example"]], ['a_dom', 'a_comp', 'b_upper']],
            // Kept: no value2 (text), a value2 that does not hold the text
            ["!$t", ['a_mid', 'b_short', 'c_other']],
            ["!$hash", array_diff(array_keys($this->ids), ['a_hash'])],
            [[$t, "!$t.example"], ['a_url', 'a_hash', 'b_accent', 'b_pct']],
            [['NOT' => [$t, "x$t"]], ['b_short', 'c_other']],
        ];
        foreach ($cases as $case) {
            list($value, $expected) = $case;
            $this->assertSame($this->ids(...$expected), $this->select($this->filter($value)), json_encode($value));
        }
    }

    public function testATermThatIsNoSearchTextIsRefused()
    {
        $terms = [['OR' => [['nested']]], "\xff\xfe", [$this->t, "!\xc3"]];
        foreach ($terms as $term) {
            try {
                $this->filter($term);
                $this->fail('Accepted ' . bin2hex(json_encode($term, JSON_INVALID_UTF8_SUBSTITUTE)));
            } catch (BadRequestException $e) {
                $this->assertStringContainsString('Invalid value_search filter', $e->getMessage());
                $this->assertSame(400, $e->getCode());
            }
        }
        $this->expectException(BadRequestException::class);
        $params = ['value_search' => "\xff"];
        $this->attribute->buildFilterConditions($this->user, $params, true);
    }

    public function testTheAttributeRestSearchTakesTheFilter()
    {
        $t = $this->t;
        $fetched = function (array $params) {
            // Bounded, so that a filter left out fails rather than reads every attribute
            $params['eventid'] = $this->events;
            $conditions = $this->attribute->buildFilterConditions($this->user, $params, true);
            $found = $this->attribute->fetchAttributes($this->user, [
                'conditions' => $conditions,
                'flatten' => 1,
            ]);
            $ids = array_map('intval', array_column(array_column($found, 'Attribute'), 'id'));
            sort($ids);
            return $ids;
        };

        $this->clearLog();
        $this->assertSame($this->ids('a_dom', 'a_comp', 'b_upper'), $fetched(['value_search' => "$t.example"]));
        // Bounded by eventid: checked per row, nothing read ahead
        $this->assertSame([], $this->resolves());
        $this->assertNotEmpty($this->statements('/`value1_id` IN \(SELECT `id` FROM `attribute_values` WHERE `value` LIKE.*`Attribute`.`event_id` IN/'));
        $this->assertSame($this->ids('a_comp'), $fetched(['value_search' => "$t.example", 'type' => 'domain|ip']));
        $this->assertSame($this->ids('a_hash'), $fetched(['value_search' => $t, 'value' => "$t.exe"]));
    }

    public function testTheEventScopeMatchesEventsHoldingAMatch()
    {
        $t = $this->t;
        list($first, $second, $third) = $this->events;
        $cases = [
            ["x$t", [$first]],
            ["$t.example", [$first, $second]],
            [["x$t", "$t café"], [$first, $second]],
            [['AND' => ["x$t", "$t café"]], []],
            ["!$t", [$third]],
        ];
        foreach ($cases as $case) {
            list($value, $expected) = $case;
            $this->clearLog();
            $this->assertSame($expected, $this->eventIds(['eventid' => $this->events, 'value_search' => $value]), json_encode($value));
            $events = $this->statements('/`events` AS `Event`/');
            $this->assertCount(1, $events);
            $this->assertStringContainsString('value1_id', $events[0]);
            $this->assertNotRegExp('/value[12](?!_id)|MATCH\(/', $events[0]);
            // Bounded by eventid: checked per row, nothing read ahead
            $this->assertSame([], $this->resolves());
            $this->assertStringContainsString('IN (SELECT id FROM attribute_values WHERE value LIKE', $events[0]);
            // One subquery per term, not wrapped in another that runs per event
            $this->assertNotRegExp('/WHERE\s+`Event`.`id`\s+(?:NOT )?IN \(SELECT event_id FROM attributes AS Attribute\s+WHERE\s+`Event`.`id`/', $events[0]);
        }
        // Unbounded: the dictionary is read ahead, no other event holds the token
        $this->clearLog();
        $this->assertSame([$first, $second], $this->eventIds(['value_search' => $t]));
        $this->assertCount(1, $this->statements('/MATCH\(`value`\)/'));

        // A negation keeps an event without attributes
        $this->exec(sprintf(
            "INSERT INTO events (org_id, orgc_id, user_id, date, info, uuid, analysis, sharing_group_id, threat_level_id, distribution) VALUES (1, 1, 1, CURDATE(), 'value-search', '%s', 0, 0, 4, 0)",
            CakeText::uuid()
        ));
        $empty = (int)$this->exec('SELECT LAST_INSERT_ID() AS id')[0]['id'];
        $this->assertSame([$third, $empty], $this->eventIds(['eventid' => array_merge($this->events, [$empty]), 'value_search' => "!$t"]));
    }

    public function testTheObjectScopeMatchesObjectsHoldingAMatch()
    {
        $t = $this->t;
        $objects = $this->createObjects();
        list($a, $other) = $objects;
        $cases = [
            [['value_search' => "x$t"], [$a]],
            [['value_search' => "$t 50%"], [$other]],
            [['value_search' => ["x$t", "$t 50%"]], [$a, $other]],
            [['value_search' => ['AND' => ["x$t", "$t 50%"]]], []],
            // An object without attributes holds no text, also for a negation
            [['value_search' => "!x$t", 'eventid' => $this->events], [$other]],
            [['value_search' => $t, 'type' => 'text'], [$other]],
        ];
        foreach ($cases as $case) {
            list($params, $expected) = $case;
            $this->clearLog();
            $this->assertSame($expected, $this->objectIds($params, $objects), json_encode($params));
            $statements = $this->statements('/`objects`(?: AS)? `Object`/');
            $this->assertCount(1, $statements);
            $this->assertNotRegExp('/value[12](?!_id)/', $statements[0]);
        }
    }
}
