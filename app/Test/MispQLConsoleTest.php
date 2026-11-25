<?php
/**
 * What the query console page is given: the language pack and the history.
 * Pure PHPUnit, no database.
 */
if (!function_exists('__')) {
    function __($singular, $args = null)
    {
        $arguments = array_slice(func_get_args(), 1);
        return $arguments ? vsprintf($singular, $arguments) : $singular;
    }
}
require_once __DIR__ . '/MispQLFixtures.php';
require_once __DIR__ . '/../Lib/Tools/MispQL/MispQLHistory.php';
require_once __DIR__ . '/../Lib/Tools/MispQL/MispQLLanguagePack.php';

use PHPUnit\Framework\TestCase;

class MispQLConsoleTestBackend implements MispQLBackend
{
    /** @var string[] */
    public $tables = ['attributes', 'tags'];

    /** @var string[] tables described, in order */
    public $described = [];

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
                'fields' => ['id' => ['type' => 'int', 'operators' => ['=', 'IN'], 'level' => ['attribute']]],
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
            ['type' => 'int', 'operators' => ['=', 'IN'], 'level' => ['attribute']],
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
        });
    }
}
