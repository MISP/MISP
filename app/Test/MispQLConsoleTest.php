<?php
/**
 * What the query console page is given: the language pack and the history.
 * Pure PHPUnit, no database.
 */
require_once __DIR__ . '/MispQLFixtures.php';
require_once __DIR__ . '/../Lib/Tools/MispQL/MispQLHistory.php';
require_once __DIR__ . '/../Lib/Tools/MispQL/MispQLLanguagePack.php';
require_once __DIR__ . '/../Lib/Tools/MispQL/MispQLFieldDocs.php';

use PHPUnit\Framework\TestCase;

class MispQLConsoleTestBackend implements MispQLBackend
{
    /** @var string[] */
    public $tables = ['attributes', 'tags'];

    /** @var string[] tables described, in order */
    public $described = [];

    /** @var array table => fields beside `id` */
    public $fields = [];

    public function validate($table, array $body)
    {
    }

    public function search($table, array $body)
    {
        throw new LogicException('the pack runs no search');
    }

    public function describe($table)
    {
        $this->described[] = $table;
        return [
            'tables' => [$table => [
                'endpoint' => "/$table/queryDescribe",
                'fields' => ['id' => ['type' => 'int', 'operators' => ['=', 'IN'], 'level' => ['attribute']]]
                    + ($this->fields[$table] ?? []),
                'sortable' => ['id'],
            ]],
            'limits' => ['max_depth' => 5, 'max_nodes' => 50],
        ];
    }

    public function tables()
    {
        return $this->tables;
    }

    public function whoami()
    {
        throw new LogicException('the pack asks no whoami');
    }
}

class MispQLConsoleTest extends TestCase
{
    public function testPackListsOnlyTheTablesTheUserMayQuery()
    {
        $backend = new MispQLConsoleTestBackend();
        $pack = $this->pack($backend);
        $this->assertSame(['attributes', 'tags'], array_keys((array)$pack['tables']));
        $this->assertSame(['attributes', 'tags'], $backend->described);
    }

    public function testPackTable()
    {
        $pack = $this->pack(new MispQLConsoleTestBackend());
        $attributes = $pack['tables']->attributes;
        $this->assertSame('/attributes/restSearch', $attributes['endpoint']);
        $this->assertSame('Attributes, each with its event and its tags', $attributes['description']);
        $this->assertSame(
            [
                'type' => 'int', 'operators' => ['=', 'IN'], 'level' => ['attribute'],
                'description' => MispQLFieldDocs::describe('attributes', 'id'),
            ],
            $attributes['fields']->id
        );
        $this->assertSame(['csv', 'json'], $attributes['formats']);
        $this->assertSame(
            ['id', 'event_id', 'category', 'type', 'value', 'to_ids', 'timestamp', 'Tag'],
            $attributes['default_columns']
        );
        $this->assertSame('Event.info', $attributes['aliases']->eventinfo);
        $this->assertSame('Event.publish_timestamp', $attributes['order_by']->publish_timestamp);
        $this->assertSame('id', $attributes['order_by']->id);
    }

    public function testPackLinks()
    {
        $pack = $this->pack(new MispQLConsoleTestBackend());
        $links = $pack['tables']->attributes['links'];
        $this->assertSame('Attribute', $links->id);
        $this->assertSame('Value', $links->value);
        $this->assertSame('Event', $links->event_id);
        $this->assertSame('Organisation', $links->{'Event.Orgc.id'});
        $this->assertSame('Tag', $pack['tables']->tags['links']->id);
        $this->assertSame('Organisation', $pack['tables']->tags['links']->org_id);
    }

    public function testPackPagesFollowTheTablesTheUserMayQuery()
    {
        $pack = $this->pack(new MispQLConsoleTestBackend());
        $this->assertSame([
            'Attribute' => '/attributes/view/%s',
            'Value' => '/values/view/%s',
        ], (array)$pack['pages'], 'a tag opens the events carrying it, which this user cannot search');

        $backend = new MispQLConsoleTestBackend();
        $backend->tables = ['events', 'tags'];
        $this->assertSame('/events/index/searchtag:%s', $this->pack($backend)['pages']->Tag);

        $backend = new MispQLConsoleTestBackend();
        $backend->tables = [];
        $this->assertStringContainsString(
            '"pages":{"Value":"/values/view/%s"}',
            json_encode($this->pack($backend), JSON_UNESCAPED_SLASHES)
        );
    }

    public function testAnalystDataLinksReadTheirTypeFromTheRow()
    {
        $links = MispQLFixtures::tables()->links('relationships');
        $this->assertSame(['type_from' => 'object_type'], $links['object_uuid']);
        $this->assertSame(['type_from' => 'related_object_type'], $links['related_object_uuid']);
        $this->assertSame(['type' => 'Value', 'by' => 'sha256'], $links['related_object_sha256']);
        $this->assertStringContainsString(
            '"object_uuid":{"type_from":"object_type"}',
            json_encode((object)$links)
        );
    }

    public function testEveryLinkOpensAPage()
    {
        $tables = MispQLFixtures::tables();
        $pages = $tables->pages($tables->names());
        $this->assertSame(array_keys(MispQLTables::PAGES), array_keys($pages));
        foreach ($pages as $type => $url) {
            $this->assertSame(1, substr_count($url, '%s'), $type);
        }
        foreach ($tables->names() as $name) {
            $links = $tables->links($name);
            $this->assertArrayHasKey('id', $links, $name);
            foreach ($links as $column => $link) {
                if (is_array($link) && isset($link['type_from'])) {
                    $this->assertContains($link['type_from'], $tables->get($name)['columns'], "$name.$column");
                    continue;
                }
                $type = is_array($link) ? $link['type'] : $link;
                $this->assertArrayHasKey($type, $pages, "$name.$column");
            }
        }
    }

    public function testPackOffersValuesFromListsSharedByName()
    {
        $string = ['type' => 'string', 'operators' => ['='], 'level' => ['attribute']];
        $int = ['type' => 'int', 'operators' => ['='], 'level' => ['attribute']];
        $backend = new MispQLConsoleTestBackend();
        $backend->tables = ['attributes', 'events', 'galaxy_clusters'];
        $backend->fields = [
            'attributes' => ['type' => $string, 'distribution' => $int, 'threat_level_id' => $int],
            'events' => ['type' => $string, 'distribution' => $int, 'analysis' => $int],
            'galaxy_clusters' => ['type' => $string, 'distribution' => $int],
        ];
        $asked = [];
        $pack = MispQLLanguagePack::build(MispQLFixtures::tables(), $backend, function () {
            return ['json'];
        }, function ($list) use (&$asked) {
            $asked[] = $list;
            return $list === 'analysis' ? [] : [['value' => "$list-1"], ['value' => "$list-2"]];
        });
        $attributes = $pack['tables']->attributes['fields'];
        $events = $pack['tables']->events['fields'];
        $this->assertSame('attribute_types', $attributes->type['values']);
        $this->assertSame('attribute_types', $events->type['values']);
        $this->assertSame('distribution_inherit', $attributes->distribution['values']);
        $this->assertSame('distribution', $events->distribution['values'], 'an event cannot inherit');
        $this->assertSame('distribution', $pack['tables']->galaxy_clusters['fields']->distribution['values']);
        $this->assertSame('galaxy_types', $pack['tables']->galaxy_clusters['fields']->type['lookup']);
        $clusters = $pack['tables']->galaxy_clusters['fields'];
        $this->assertArrayNotHasKey('values', $clusters->type, 'a galaxy type, not an attribute type');
        $this->assertArrayNotHasKey('values', $events->analysis, 'an empty list is not offered');
        $this->assertArrayNotHasKey('values', $attributes->id);
        $this->assertSame(
            ['attribute_types', 'distribution_inherit', 'threat_levels', 'analysis', 'distribution'],
            $asked,
            'each list read once, and only for a field the user can query'
        );
        $this->assertSame(
            ['attribute_types', 'distribution_inherit', 'threat_levels', 'distribution'],
            array_keys((array)$pack['values'])
        );
        $this->assertSame(
            [['value' => 'threat_levels-1'], ['value' => 'threat_levels-2']],
            $pack['values']->threat_levels
        );
    }

    public function testPackLooksUpThroughThePickers()
    {
        $string = ['type' => 'string', 'operators' => ['='], 'level' => ['event']];
        $backend = new MispQLConsoleTestBackend();
        $backend->tables = ['attributes', 'organisations'];
        $backend->fields = [
            'attributes' => ['tags' => $string, 'org' => $string],
            'organisations' => ['name' => $string],
        ];
        $pack = $this->pack($backend);
        $this->assertSame('tags', $pack['tables']->attributes['fields']->tags['lookup']);
        $this->assertSame('organisations', $pack['tables']->attributes['fields']->org['lookup']);
        $this->assertSame('organisations', $pack['tables']->organisations['fields']->name['lookup']);
        $this->assertSame(['tags', 'organisations'], array_keys((array)$pack['sources']));
        $this->assertSame(
            ['/tags/pickerSearch', '/galaxy_clusters/pickerSearch'],
            array_column($pack['sources']->tags, 'url'),
            'tag names, then the clusters\' tag names'
        );
        $json = json_encode($this->pack(new MispQLConsoleTestBackend()));
        $this->assertStringContainsString('"values":{},"sources":{}', $json);
    }

    public function testEveryListAndLookupExists()
    {
        $tables = MispQLFixtures::tables();
        foreach ($tables->names() as $name) {
            foreach ($tables->values($name) as $field => $list) {
                $this->assertContains($list, MispQLTables::VALUE_LISTS, "$name.$field");
            }
            foreach ($tables->lookups($name) as $field => $source) {
                $this->assertArrayHasKey($source, MispQLTables::SOURCES, "$name.$field");
                $this->assertArrayNotHasKey($field, $tables->values($name), "$name.$field: a list or a lookup");
            }
        }
        foreach (MispQLTables::SOURCES as $source => $pickers) {
            foreach ($pickers as $picker) {
                $this->assertRegExp('#^/[a-z_]+/picker[A-Z][a-z]+$#', $picker['url'], $source);
                $this->assertIsString($picker['insert'], $source);
            }
        }
    }

    public function testEveryFieldSaysWhatItMeans()
    {
        $tables = MispQLFixtures::tables();
        foreach ($tables->names() as $name) {
            $fields = MispQLFixtures::fieldNames($name);
            $this->assertContains('id', $fields, "$name: its fields are read");
            foreach ($fields as $field) {
                $sentence = MispQLFieldDocs::describe($name, $field);
                $this->assertIsString($sentence, "$name.$field has no sentence in MispQLFieldDocs");
                $this->assertRegExp('/^[A-Z].*\.$/s', $sentence, "$name.$field");
            }
        }
        $this->assertContains('meta.<key>', MispQLFixtures::fieldNames('galaxy_clusters'));
        $this->assertContains('note', MispQLFixtures::fieldNames('notes'), 'the type\'s own fields');
        $this->assertContains('locked', MispQLFixtures::fieldNames('notes'), 'and those every type has');
    }

    public function testFieldSentencesFollowTheTable()
    {
        $this->assertNotSame(
            MispQLFieldDocs::describe('attributes', 'tags'),
            MispQLFieldDocs::describe('events', 'tags'),
            'on events, tags selects events'
        );
        $this->assertSame(
            MispQLFieldDocs::describe('attributes', 'eventinfo'),
            MispQLFieldDocs::describe('event_reports', 'eventinfo'),
            'a name means the same wherever it does'
        );
        $this->assertStringContainsString('5', MispQLFieldDocs::describe('attributes', 'distribution'));
        $this->assertStringNotContainsString('5', MispQLFieldDocs::describe('events', 'distribution'));
        $this->assertNull(MispQLFieldDocs::describe('tags', 'nope'));
    }

    public function testPackLeavesOutAMissingSentence()
    {
        $backend = new MispQLConsoleTestBackend();
        $backend->fields = ['tags' => ['nope' => ['type' => 'int', 'operators' => ['='], 'level' => ['tag']]]];
        $pack = $this->pack($backend);
        $this->assertArrayNotHasKey('description', $pack['tables']->tags['fields']->nope);
    }

    public function testPackLanguage()
    {
        $pack = $this->pack(new MispQLConsoleTestBackend());
        $this->assertSame('1.0', $pack['language']);
        $this->assertContains('WHOAMI', $pack['keywords']);
        $this->assertCount(24, $pack['keywords']);
        $this->assertSame(['USE', 'SHOW DATABASES'], $pack['client_statements']);
        $this->assertSame(['table', 'flat'], $pack['renderings']);
        $this->assertSame(
            ['max_depth' => 5, 'max_nodes' => 50, 'max_length' => 1048576, 'max_nesting' => 64],
            (array)$pack['limits']
        );
    }

    public function testPackEncodesMapsAsObjects()
    {
        $json = json_encode($this->pack(new MispQLConsoleTestBackend()));
        $this->assertStringContainsString('"aliases":{}', $json, 'tags have no alias');
        $decoded = json_decode($json);
        $this->assertIsObject($decoded->tables);
        $this->assertIsObject($decoded->limits);
    }

    public function testPackWithNoTable()
    {
        $backend = new MispQLConsoleTestBackend();
        $backend->tables = [];
        $json = json_encode($this->pack($backend));
        $this->assertStringContainsString('"tables":{}', $json);
        $this->assertStringContainsString('"limits":{"max_length":1048576,"max_nesting":64}', $json);
    }

    public function testHistoryPutsTheStatementOnTopOnce()
    {
        $entries = MispQLHistory::add([], ' SHOW TABLES ', 100);
        $entries = MispQLHistory::add($entries, 'WHOAMI', 200);
        $entries = MispQLHistory::add($entries, "SHOW TABLES\n", 300);
        $this->assertSame([
            ['statement' => 'SHOW TABLES', 'ran_at' => 300],
            ['statement' => 'WHOAMI', 'ran_at' => 200],
        ], $entries);
    }

    public function testHistoryKeepsFiftyEntries()
    {
        $entries = [];
        for ($i = 1; $i <= 60; $i++) {
            $entries = MispQLHistory::add($entries, "SELECT * FROM tags LIMIT $i", $i);
        }
        $this->assertCount(MispQLHistory::MAX_ENTRIES, $entries);
        $this->assertSame('SELECT * FROM tags LIMIT 60', $entries[0]['statement']);
        $this->assertSame('SELECT * FROM tags LIMIT 11', $entries[49]['statement']);
    }

    public function testHistoryStaysUnderItsSize()
    {
        $big = "SELECT * FROM attributes WHERE value = '" . str_repeat('x', 200000) . "' LIMIT 1";
        $entries = MispQLHistory::add([], 'WHOAMI', 1);
        $entries = MispQLHistory::add($entries, $big . ' -- 1', 2);
        $entries = MispQLHistory::add($entries, $big . ' -- 2', 3);
        $this->assertSame(['-- 2', '-- 1', 'WHOAMI'], array_map(function ($e) {
            return substr($e['statement'], -4) === 'OAMI' ? 'WHOAMI' : substr($e['statement'], -4);
        }, $entries));
        $entries = MispQLHistory::add($entries, $big . ' -- 3', 4);
        $this->assertCount(2, $entries, 'the oldest large entry and what follows it are dropped');
        $this->assertLessThanOrEqual(MispQLHistory::MAX_BYTES, strlen(json_encode($entries)));
    }

    public function testHistoryRefusesAStatementTooLargeAlone()
    {
        $huge = str_repeat('é', MispQLHistory::MAX_BYTES / 6);
        $this->assertNull(MispQLHistory::add([], $huge, 1), 'escaped, it no longer fits');
        $this->assertNull(MispQLHistory::add([], '   ', 1));
    }

    public function testHistoryEntriesDropWhatIsNotAnEntry()
    {
        $this->assertSame([], MispQLHistory::entries(null));
        $this->assertSame([], MispQLHistory::entries('SHOW TABLES'));
        $this->assertSame([['statement' => 'WHOAMI', 'ran_at' => 5]], MispQLHistory::entries([
            ['statement' => 'WHOAMI', 'ran_at' => '5'],
            ['statement' => '', 'ran_at' => 6],
            ['statement' => ['x'], 'ran_at' => 7],
            ['ran_at' => 8],
            'SHOW TABLES',
        ]));
    }

    private function pack(MispQLBackend $backend)
    {
        return MispQLLanguagePack::build(MispQLFixtures::tables(), $backend, function ($table) {
            return ['csv', 'json'];
        }, function ($list) {
            return [['value' => $list]];
        });
    }
}
