<?php
/**
 * The value_cidr restSearch filter. An attribute matches when its value1 or
 * value2 is an address or CIDR overlapping one of the filter's, i.e. inside
 * it or holding it, in any spelling; IPv4 sits in no IPv6 range wider than
 * the v4-mapped block. The attribute, event and object scopes take OR, AND
 * and NOT terms; a negation keeps attributes without a value2. The facet is
 * read ahead, or inside the statement when too many values start inside a
 * range. A term that is not an address or CIDR is refused.
 *
 * The fixtures sit in a /24 and a /64 that no stored value overlaps, plus
 * ::ffff:0:0/96 and ::/0, which hold every IPv4 and IPv6 address. A save
 * stores /32 as the address and compresses IPv6, so those spellings are made
 * by pointing an attribute at an interned value.
 *
 * Every test runs in a transaction that is rolled back. Skipped unless
 * ATTRIBUTE_VALUE_DB_TESTS is set, and it boots the real application, so it
 * must run on its own:
 *     ATTRIBUTE_VALUE_DB_TESTS=1 ./app/Vendor/bin/phpunit app/Test/AttributeValueCidrSearchDbTest.php
 */

use PHPUnit\Framework\TestCase;

class AttributeValueCidrSearchDbTest extends TestCase
{
    const IPV4 = [
        'a_ip', 'a_text', 'a_composite', 'a_port', 'a_slash32',
        'b_cidr28', 'b_upper', 'b_mapped', 'b_port_out',
        'c_cidr24', 'c_hostbits', 'c_v4all',
    ];

    const IPV6 = ['a_ip6', 'a_ip6_long', 'c_wide6', 'c_cidr6'];

    private static $booted = false;

    /** @var MispAttribute */
    private $attribute;

    /** @var Event */
    private $event;

    /** @var DboSource */
    private $db;

    /** @var array */
    private $user;

    /** @var string the first three octets of the IPv4 block */
    private $b;

    /** @var string the first four groups of the IPv6 block */
    private $p;

    /** @var int[] */
    private $events;

    /** @var array name => attribute id */
    private $ids = [];

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
            App::uses('ValueFacetTool', 'Tools');
            AttributeValue::$strictConditions = true;
            self::$booted = true;
        }
        $this->attribute = ClassRegistry::init('MispAttribute');
        $this->event = $this->attribute->Event;
        $this->db = $this->attribute->getDataSource();
        if (!($this->db instanceof Mysql)) {
            // Skipped before the fixture exists: nothing for tearDown to clean up
            $this->db = null;
            $this->markTestSkipped('MySQL/MariaDB only.');
        }
        $this->cachedMethods = $this->db->cacheMethods;
        $this->fullDebug = $this->db->fullDebug;
        $this->db->begin();
        $this->user = ClassRegistry::init('User')->getAuthUser(1);
        // The analyst data behaviour reads the request's user from here
        $this->currentUserId = Configure::read('CurrentUserId');
        Configure::write('CurrentUserId', $this->user['id']);
        $this->b = substr($this->freeBlock(function () {
            return sprintf('%d.%d.%d.0/24', random_int(1, 223), random_int(0, 255), random_int(0, 255));
        }), 0, -5);
        $this->p = substr($this->freeBlock(function () {
            return vsprintf('2001:db8:%x:%x::/64', [random_int(4096, 65535), random_int(4096, 65535)]);
        }), 0, -5);
        $this->events = array_map('intval', $this->event->find('column', [
            'order' => ['Event.id' => 'ASC'],
            'fields' => ['Event.id'],
            'limit' => 3,
        ]));
        $this->createFixture();
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
     * A block no facet row overlaps or holds.
     *
     * @param callable $candidate
     * @return string
     */
    private function freeBlock(callable $candidate)
    {
        for ($try = 0; $try < 20; $try++) {
            $cidr = $candidate();
            $range = ValueFacetTool::ipRange($cidr);
            $taken = $this->exec(sprintf(
                "SELECT 1 FROM value_ip_ranges WHERE ip_start <= X'%s' AND ip_end >= X'%s' LIMIT 1",
                bin2hex($range[1]),
                bin2hex($range[0])
            ));
            if (empty($taken)) {
                return $cidr;
            }
        }
        $this->fail('No free address block found.');
    }

    private function createFixture()
    {
        $b = $this->b;
        $p = $this->p;
        list($first, $second, $third) = $this->events;
        $this->add([
            'a_ip' => [$first, 'ip-dst', "$b.10"],
            'a_text' => [$first, 'text', "$b.11"],
            'a_composite' => [$first, 'domain|ip', "cidr-search.example|$b.12"],
            'a_port' => [$first, 'ip-dst|port', "$b.13|443"],
            'a_slash32' => [$first, 'ip-src', "$b.14"],
            'a_domain' => [$first, 'domain', 'cidr-search.example'],
            'a_ip6' => [$first, 'ip-dst', "$p::7"],
            'a_ip6_long' => [$first, 'ip-dst', "$p::8"],
            'b_cidr28' => [$second, 'ip-dst', "$b.0/28"],
            'b_upper' => [$second, 'ip-dst', "$b.128/25"],
            'b_mapped' => [$second, 'ip-dst', "::ffff:$b.10"],
            'b_port_out' => [$second, 'ip-dst|port', "$b.200|80"],
            'c_cidr24' => [$third, 'ip-dst', "$b.0/24"],
            'c_hostbits' => [$third, 'ip-src', "$b.99/24"],
            'c_v4all' => [$third, 'ip-dst', '::ffff:0:0/96'],
            'c_wide6' => [$third, 'ip-dst', '::/0'],
            'c_cidr6' => [$third, 'ip-dst', "$p::/64"],
        ]);
        $groups = array_map(function ($g) {
            return sprintf('%04x', hexdec($g));
        }, explode(':', $p));
        $this->legacy('a_slash32', "$b.14/32");
        $this->legacy('a_ip6_long', implode(':', $groups) . ':0000:0000:0000:0008');
    }

    /**
     * Attributes saved without correlating, the text columns diverged and
     * hidden.
     *
     * @param array $specs name => [event id, type, value]
     * @return void
     */
    private function add(array $specs)
    {
        $added = [];
        foreach ($specs as $name => $spec) {
            list($eventId, $type, $value) = $spec;
            $this->attribute->create();
            $saved = $this->attribute->save(['Attribute' => [
                'event_id' => $eventId,
                'category' => $this->attribute->typeDefinitions[$type]['default_category'],
                'type' => $type,
                'value' => $value,
                'distribution' => 5,
                'to_ids' => 0,
                'disable_correlation' => 1,
            ]]);
            $this->assertNotFalse($saved, $name . json_encode($this->attribute->validationErrors));
            $added[] = $this->ids[$name] = (int)$this->attribute->id;
        }
        AttributeValueTextSupport::diverge($this->db, 'attributes', sprintf(
            "UPDATE attributes SET value1 = 'column-x', value2 = IF(value2 = '', '', 'column-x') WHERE id IN (%s)",
            implode(', ', $added)
        ));
        $this->hideTextColumns();
    }

    /**
     * Point an attribute at a spelling a save would have normalised away.
     *
     * @param string $name
     * @param string $value1
     * @return void
     */
    private function legacy($name, $value1)
    {
        $id = ClassRegistry::init('AttributeValue')->intern($value1);
        $this->exec(sprintf('UPDATE attributes SET value1_id = %d WHERE id = %d', $id, $this->ids[$name]));
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

    private function ids(...$names)
    {
        $ids = [];
        foreach ($names as $name) {
            $ids[] = $this->ids[$name];
        }
        sort($ids);
        return $ids;
    }

    private function except(array $names)
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
        $params = ['value_cidr' => $value];
        return $this->event->set_filter_value_cidr($params, [], ['filter' => 'value_cidr', 'context' => 'Attribute']);
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
                "INSERT INTO objects (name, `meta-category`, template_uuid, template_version, event_id, uuid, timestamp, distribution, comment, deleted) VALUES ('ip-port', 'network', '%s', 1, %d, '%s', %d, 5, '', 0)",
                CakeText::uuid(),
                $eventId,
                CakeText::uuid(),
                time()
            ));
            $objects[] = (int)$this->exec('SELECT LAST_INSERT_ID() AS id')[0]['id'];
        }
        $this->exec(sprintf('UPDATE attributes SET object_id = %d WHERE id = %d', $objects[0], $this->ids['a_ip6']));
        $this->exec(sprintf('UPDATE attributes SET object_id = %d WHERE id = %d', $objects[1], $this->ids['b_port_out']));
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

    public function testAnAddressMatchesItsSpellingsAndTheRangesHoldingIt()
    {
        $b = $this->b;
        $p = $this->p;
        $tenth = ['a_ip', 'b_mapped', 'b_cidr28', 'c_cidr24', 'c_hostbits', 'c_v4all'];
        $cases = [
            ["$b.10", $tenth],
            ["::ffff:$b.10", $tenth],
            ["$b.10/32", $tenth],
            [" $b.10 ", $tenth],
            // value2 of a composite
            ["$b.12", ['a_composite', 'b_cidr28', 'c_cidr24', 'c_hostbits', 'c_v4all']],
            ["$b.14", ['a_slash32', 'b_cidr28', 'c_cidr24', 'c_hostbits', 'c_v4all']],
            ["$p::7", ['a_ip6', 'c_cidr6', 'c_wide6']],
            [strtoupper("$p::8"), ['a_ip6_long', 'c_cidr6', 'c_wide6']],
            ["$p::8/128", ['a_ip6_long', 'c_cidr6', 'c_wide6']],
        ];
        foreach ($cases as $case) {
            list($value, $expected) = $case;
            $this->clearLog();
            $this->assertSame($this->ids(...$expected), $this->select($this->filter($value)), $value);
            // An address only needs the ranges holding it
            $this->assertCount(1, $this->statements('/FROM `value_ip_ranges`/'), $value);
        }
    }

    public function testARangeMatchesWhatItHoldsAndWhatHoldsIt()
    {
        $b = $this->b;
        $p = $this->p;
        $lower = ['a_ip', 'a_text', 'a_composite', 'a_port', 'a_slash32', 'b_cidr28', 'b_mapped', 'c_cidr24', 'c_hostbits', 'c_v4all'];
        $cases = [
            ["$b.0/24", self::IPV4],
            // Host bits under the mask are ignored
            ["$b.77/24", self::IPV4],
            ["::ffff:$b.0/120", self::IPV4],
            ["$b.0/28", $lower],
            ["$b.128/25", ['b_upper', 'b_port_out', 'c_cidr24', 'c_hostbits', 'c_v4all']],
            ["$p::/64", self::IPV6],
            ["$p::/96", ['a_ip6', 'a_ip6_long', 'c_cidr6', 'c_wide6']],
            // IPv4 is in no IPv6 range wider than the v4-mapped block
            ['::/0', self::IPV6],
            ['::/80', ['c_wide6']],
        ];
        foreach ($cases as $case) {
            list($value, $expected) = $case;
            $this->clearLog();
            $conditions = $this->filter($value);
            $this->assertCount(2, $this->statements('/FROM `value_ip_ranges`/'), $value);
            $this->clearLog();
            $this->assertSame($this->ids(...$expected), $this->select($conditions), $value);
            // Read ahead: the find names the ids
            $find = $this->statements('/`attributes` AS `Attribute`/');
            $this->assertCount(1, $find, $value);
            $this->assertStringNotContainsString('value_ip_ranges', $find[0], $value);
            $this->assertNotRegExp('/value[12](?!_id)/', $find[0], $value);
        }
    }

    public function testTheAttributeScopeTakesOrAndAndNot()
    {
        $b = $this->b;
        $p = $this->p;
        $lower = ['a_ip', 'a_text', 'a_composite', 'a_port', 'a_slash32', 'b_cidr28', 'b_mapped', 'c_cidr24', 'c_hostbits', 'c_v4all'];
        $cases = [
            [["$b.200", "$p::7"], ['b_upper', 'b_port_out', 'c_cidr24', 'c_hostbits', 'c_v4all', 'a_ip6', 'c_cidr6', 'c_wide6']],
            ["$b.200&&$p::7", ['b_upper', 'b_port_out', 'c_cidr24', 'c_hostbits', 'c_v4all', 'a_ip6', 'c_cidr6', 'c_wide6']],
            // Both halves: only what holds both
            [['AND' => ["$b.0/28", "$b.128/25"]], ['c_cidr24', 'c_hostbits', 'c_v4all']],
            // Kept: no value2 (a_domain), a value2 that is no address (b_port_out)
            ["!$b.0/28", array_diff(array_keys($this->ids), $lower)],
            [['NOT' => ["$b.0/28", "$p::/64"]], ['a_domain', 'b_upper', 'b_port_out']],
            [["$b.0/24", "!$b.0/28"], ['b_upper', 'b_port_out']],
        ];
        foreach ($cases as $case) {
            list($value, $expected) = $case;
            $this->assertSame($this->ids(...$expected), $this->select($this->filter($value)), json_encode($value));
        }
    }

    public function testAnOverflowReadsTheFacetInsideTheStatement()
    {
        $b = $this->b;
        $p = $this->p;
        $AttributeValue = $this->attribute->loadAttributeValue();
        $cases = [
            [["$b.0/24"], false],
            [["$b.0/28", "$p::/64"], false],
            [["$b.0/28"], true],
            [["$b.128/25", "$p::7"], true],
        ];
        foreach ($cases as $case) {
            list($cidrs, $not) = $case;
            $ranges = array_map(['ValueFacetTool', 'ipRange'], $cidrs);
            $expected = $this->select($AttributeValue->cidrCondition($ranges, 'Attribute', $not));
            $this->assertNotEmpty($expected);
            $this->clearLog();
            $this->assertSame($expected, $this->select($AttributeValue->cidrCondition($ranges, 'Attribute', $not, 1)), json_encode($case));
            $find = $this->statements('/`attributes` AS `Attribute`/');
            $this->assertCount(1, $find);
            $this->assertStringContainsString(
                sprintf('`Attribute`.`value2_id` %s (SELECT `value_id` FROM `value_ip_ranges` WHERE', $not ? 'NOT IN' : 'IN'),
                $find[0]
            );
        }
    }

    public function testARangeNothingOverlapsMatchesNothing()
    {
        // Without the two ranges holding every address
        $this->exec(sprintf(
            'DELETE f FROM value_ip_ranges f JOIN attributes a ON a.value1_id = f.value_id WHERE a.id IN (%d, %d)',
            $this->ids['c_v4all'],
            $this->ids['c_wide6']
        ));
        $free = $this->freeBlock(function () {
            return sprintf('%d.%d.%d.0/24', random_int(1, 223), random_int(0, 255), random_int(0, 255));
        });

        $this->assertSame([], $this->select($this->filter($free)));
        $this->assertSame($this->except([]), $this->select($this->filter("!$free")));
        $this->assertSame(
            $this->ids('c_cidr24', 'c_hostbits'),
            $this->select($this->filter(['AND' => ["{$this->b}.0/28", "{$this->b}.128/25"]]))
        );
    }

    public function testATermThatIsNoAddressIsRefused()
    {
        $p = $this->p;
        $terms = ['nonsense', "{$this->b}.0/33", "$p::/129", '10.0.0.0/x', '10.0.0.0/', ['OR' => [['10.0.0.1']]], ["{$this->b}.10", '!example.org']];
        foreach ($terms as $term) {
            try {
                $this->filter($term);
                $this->fail('Accepted ' . json_encode($term));
            } catch (BadRequestException $e) {
                $this->assertStringContainsString('Invalid value_cidr filter', $e->getMessage());
                $this->assertSame(400, $e->getCode());
            }
        }
        $this->expectException(BadRequestException::class);
        $params = ['value_cidr' => '192.0.2.0/24/8'];
        $this->attribute->buildFilterConditions($this->user, $params, true);
    }

    public function testTheAttributeRestSearchTakesTheFilter()
    {
        $b = $this->b;
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

        $this->assertSame(
            $this->ids('b_upper', 'b_port_out', 'c_cidr24', 'c_hostbits', 'c_v4all'),
            $fetched(['value_cidr' => "$b.128/25"])
        );
        $this->assertSame($this->ids('b_upper', 'c_cidr24', 'c_v4all'), $fetched(['value_cidr' => "$b.128/25", 'type' => 'ip-dst']));
        $this->assertSame($this->ids('a_composite'), $fetched(['value_cidr' => "$b.0/24", 'value' => 'cidr-search.example']));
    }

    public function testTheEventScopeMatchesEventsHoldingAMatch()
    {
        $b = $this->b;
        $p = $this->p;
        list($first, $second, $third) = $this->events;
        $cases = [
            ["$b.200", [$second, $third]],
            ["$p::7", [$first, $third]],
            [["$b.200", "$p::7"], [$first, $second, $third]],
            [['AND' => ["$b.10", "$p::7"]], [$first, $third]],
            ["!$b.128/25", [$first]],
        ];
        foreach ($cases as $case) {
            list($value, $expected) = $case;
            $this->clearLog();
            $this->assertSame($expected, $this->eventIds(['eventid' => $this->events, 'value_cidr' => $value]), json_encode($value));
            $events = $this->statements('/`events` AS `Event`/');
            $this->assertCount(1, $events);
            $this->assertStringContainsString('value1_id', $events[0]);
            $this->assertNotRegExp('/value[12](?!_id)|value_ip_ranges/', $events[0]);
            // One subquery per term, not wrapped in another that runs per event
            $this->assertNotRegExp('/WHERE\s+`Event`.`id`\s+(?:NOT )?IN \(SELECT event_id FROM attributes AS Attribute\s+WHERE\s+`Event`.`id`/', $events[0]);
        }
        // Unbounded: no other event holds a value in the blocks
        $this->assertSame([$second, $third], $this->eventIds(['value_cidr' => "$b.128/25"]));

        // A negation keeps an event without attributes
        $this->exec(sprintf(
            "INSERT INTO events (org_id, orgc_id, user_id, date, info, uuid, analysis, sharing_group_id, threat_level_id, distribution) VALUES (1, 1, 1, CURDATE(), 'cidr-search', '%s', 0, 0, 4, 0)",
            CakeText::uuid()
        ));
        $empty = (int)$this->exec('SELECT LAST_INSERT_ID() AS id')[0]['id'];
        $this->assertSame([$first, $empty], $this->eventIds(['eventid' => array_merge($this->events, [$empty]), 'value_cidr' => "!$b.128/25"]));
        $this->assertSame([$second], $this->eventIds(['eventid' => array_merge($this->events, [$empty]), 'value_cidr' => ['OR' => ["$b.200"], 'NOT' => ["$p::/64"]]]));
    }

    public function testTheObjectScopeMatchesObjectsHoldingAMatch()
    {
        $b = $this->b;
        $p = $this->p;
        $objects = $this->createObjects();
        list($a, $other) = $objects;
        $cases = [
            [['value_cidr' => "$p::/64"], [$a]],
            [['value_cidr' => "$b.200"], [$other]],
            [['value_cidr' => ["$p::7", "$b.0/24"]], [$a, $other]],
            [['value_cidr' => ['AND' => ["$p::7", "$b.200"]]], []],
            // An object without attributes matches no address, also a negated one
            [['value_cidr' => "!$p::/64", 'eventid' => $this->events], [$other]],
            [['value_cidr' => "$b.0/24", 'type' => 'ip-dst|port'], [$other]],
        ];
        foreach ($cases as $case) {
            list($params, $expected) = $case;
            $this->clearLog();
            $this->assertSame($expected, $this->objectIds($params, $objects), json_encode($params));
            $statements = $this->statements('/`objects`(?: AS)? `Object`/');
            $this->assertCount(1, $statements);
            $this->assertNotRegExp('/value[12](?!_id)|value_ip_ranges/', $statements[0]);
        }
    }
}
