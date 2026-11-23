<?php
/**
 * MispQLRunner over a stand-in backend: what explain and run answer, where
 * refusals land on the text, and what reaches restSearch. Pure PHPUnit, no
 * database.
 */
require_once __DIR__ . '/MispQLFixtures.php';
require_once __DIR__ . '/../Lib/Tools/MispQL/MispQLRunner.php';

use PHPUnit\Framework\TestCase;

class MispQLRunnerTestBackend implements MispQLBackend
{
    /** @var array[] table and body of each restSearch, in order */
    public $searches = [];

    /** @var string[] tables validated, in order */
    public $validated = [];

    /** @var callable|null given the table and body, throws or returns */
    public $onValidate;

    /** @var callable given the table and body, returns the run */
    public $onSearch;

    public function validate($table, array $body)
    {
        $this->validated[] = $table;
        if ($this->onValidate !== null) {
            ($this->onValidate)($table, $body);
        }
    }

    public function search($table, array $body)
    {
        $this->searches[] = [$table, $body];
        return ($this->onSearch)($table, $body);
    }

    public function describe($table)
    {
        return [
            'tables' => [$table => [
                'endpoint' => "/$table/restSearch",
                'fields' => ['id' => ['type' => 'integer', 'operators' => ['='], 'level' => []]],
                'sortable' => ['id'],
            ]],
            'limits' => ['max_depth' => 5],
        ];
    }

    public function tables()
    {
        return ['attributes', 'tags'];
    }

    public function whoami()
    {
        return ['email' => 'admin@example.test', 'role' => 'admin', 'org' => 'ORGNAME', 'extra' => 1];
    }
}

class MispQLRunnerTest extends TestCase
{
    /** @var MispQLRunnerTestBackend */
    private $backend;

    /** @var MispQLRunner */
    private $runner;

    protected function setUp(): void
    {
        $this->backend = new MispQLRunnerTestBackend();
        $this->backend->onSearch = function () {
            return self::reply(['response' => ['Attribute' => []]]);
        };
        $this->runner = new MispQLRunner(MispQLFixtures::tables(), $this->backend);
    }

    /**
     * A run as AppController::_runRestSearch() returns it.
     */
    private static function reply($reply, $count = 0, $limit = 0)
    {
        return [
            'result' => is_string($reply) ? $reply : json_encode($reply),
            'count' => $count,
            'filters' => ['limit' => $limit],
        ];
    }

    private static function attributes($from, $to)
    {
        $rows = [];
        for ($id = $from; $id <= $to; $id++) {
            $rows[] = ['id' => (string)$id, 'value' => "v$id", 'Tag' => [['name' => "t$id"]]];
        }
        return ['response' => ['Attribute' => $rows]];
    }

    /**
     * @return array[] the errors, as decoded JSON
     */
    private function refused(callable $call)
    {
        try {
            $call();
        } catch (MispQLErrors $e) {
            return json_decode(json_encode($e->errors), true);
        }
        $this->fail('nothing was refused');
    }

    private function decoded(array $reply)
    {
        return json_decode(json_encode($reply), true);
    }

    public function testExplainReturnsEveryStatementAndReadsNoData()
    {
        $script = "SELECT id FROM attributes WHERE type = 'ip-src' LIMIT 10 OFFSET 15;\n"
            . "SELECT COUNT(*) FROM events WHERE id > 1;\n"
            . "DESCRIBE tags; SHOW TABLES; WHOAMI";
        $reply = $this->decoded($this->runner->explain($script));

        $this->assertSame('1.0', $reply['language']);
        $this->assertSame(
            ['search', 'count', 'describe', 'show_tables', 'whoami'],
            array_column($reply['statements'], 'kind')
        );
        $search = $reply['statements'][0];
        $this->assertSame([0, 66, true], [$search['start'], $search['end'], $search['validated']]);
        $this->assertSame([
            'method' => 'POST',
            'endpoint' => '/attributes/restSearch',
            'body' => ['returnFormat' => 'json', 'limit' => 10, 'page' => 2, 'query' => ['type' => 'ip-src']],
        ], $search['request']);
        $this->assertSame(3, $search['next_page']['body']['page']);
        $this->assertSame(['default', ['id'], 5], [$search['output'], $search['columns'], $search['skip']]);
        $this->assertSame(
            ['returnFormat' => 'json', 'limit' => 1, 'page' => 1, 'metadata' => 1, 'query' => ['id' => ['>' => 1]]],
            $reply['statements'][1]['request']['body']
        );
        $this->assertSame(
            ['method' => 'GET', 'endpoint' => '/tags/queryDescribe'],
            $reply['statements'][2]['request']
        );
        $this->assertSame(['attributes', 'events'], $this->backend->validated);
        $this->assertSame([], $this->backend->searches);
    }

    public function testAUseEndsValidation()
    {
        $script = 'SELECT * FROM tags LIMIT 1; USE other; SELECT * FROM attributes LIMIT 1; SHOW DATABASES';
        $statements = $this->runner->explain($script)['statements'];

        $this->assertSame([true, true, false, false], array_column($statements, 'validated'));
        $this->assertSame('other', $statements[1]['database']);
        $this->assertSame(['tags'], $this->backend->validated);
    }

    public function testExplainGathersTheErrorsOfEveryStatement()
    {
        $this->backend->onValidate = function ($table) {
            if ($table === 'tags') {
                throw new ComplexQueryException([
                    ['path' => 'query.AND[1].<unknown>', 'code' => 'unknown_field', 'message' => 'unknown field'],
                    ['path' => 'order[0]', 'code' => 'unknown_field', 'message' => 'unknown sort field'],
                    ['path' => 'nowhere', 'code' => 'bad_shape', 'message' => 'x'],
                ]);
            }
        };
        $script = "SELECT * FROM nope LIMIT 1;\nSELECT * FROM tags WHERE id = 1 AND colour = 'x' ORDER BY id LIMIT 1";
        $errors = $this->refused(function () use ($script) {
            $this->runner->explain($script);
        });

        $this->assertSame([
            ['statement' => 0, 'start' => 14, 'end' => 18, 'code' => 'unknown_table'],
            ['statement' => 1, 'start' => 64, 'end' => 70, 'code' => 'unknown_field'],
            ['statement' => 1, 'start' => 86, 'end' => 88, 'code' => 'unknown_field'],
            ['statement' => 1, 'start' => 28, 'end' => 96, 'code' => 'bad_shape'],
        ], array_map(function ($error) {
            return array_intersect_key($error, array_flip(['statement', 'start', 'end', 'code']));
        }, $errors));
        $this->assertSame('query.AND[1].<unknown>', $errors[1]['path']);
        $this->assertArrayNotHasKey('path', $errors[0]);
        $this->assertSame('colour', mb_substr($script, 64, 6));
    }

    public function testAScriptThatCannotBeSplitHasNoStatementIndex()
    {
        $errors = $this->refused(function () {
            $this->runner->explain('WHOAMI; SELECT FROM tags');
        });
        $this->assertSame([[
            'statement' => null, 'start' => 15, 'end' => 19, 'code' => 'syntax',
            'message' => 'expected *, COUNT(*) or field names',
        ]], $errors);
    }

    public function testAtMostTenErrors()
    {
        $script = implode(';', array_fill(0, 12, 'SELECT * FROM nope LIMIT 1'));
        $this->assertCount(10, $this->refused(function () use ($script) {
            $this->runner->explain($script);
        }));
    }

    public function testRunTakesOneStatement()
    {
        $errors = $this->refused(function () {
            $this->runner->run('WHOAMI; SHOW TABLES');
        });
        $this->assertSame([[
            'statement' => 0, 'start' => 8, 'end' => 19, 'code' => 'syntax', 'message' => 'run takes one statement',
        ]], $errors);

        $errors = $this->refused(function () {
            $this->runner->run(' -- café');
        });
        $this->assertSame([8, 8], [$errors[0]['start'], $errors[0]['end']]);

        // A trailing ; is not a second statement
        $this->assertSame('whoami', $this->runner->run('WHOAMI;')['kind']);
    }

    public function testClientStatementsAreRefused()
    {
        foreach (['USE other' => [0, 9], ' SHOW DATABASES' => [1, 15]] as $text => $span) {
            $errors = $this->refused(function () use ($text) {
                $this->runner->run($text);
            });
            $this->assertSame(
                ['client_statement', $span],
                [$errors[0]['code'], [$errors[0]['start'], $errors[0]['end']]]
            );
        }
    }

    public function testSelectStarReturnsMispRowsUnwrapped()
    {
        $this->backend->onSearch = function () {
            return self::reply(self::attributes(1, 2), 3);
        };
        $reply = $this->decoded($this->runner->run('SELECT * FROM attributes LIMIT 2'));

        $this->assertSame('search', $reply['kind']);
        $this->assertNull($reply['columns']);
        $this->assertSame(self::attributes(1, 2)['response']['Attribute'], $reply['rows']);
        // Only events count every match
        $this->assertNull($reply['total']);
        $this->assertSame([], $reply['warnings']);
        $this->assertSame(
            [['attributes', ['returnFormat' => 'json', 'limit' => 2, 'page' => 1]]],
            $this->backend->searches
        );
    }

    public function testAColumnListIsFlattenedAndProjected()
    {
        $this->backend->onSearch = function () {
            return self::reply(['response' => [
                [
                    'Event' => ['id' => '7', 'info' => 'x', 'Orgc' => ['name' => 'CIRCL']],
                    'Tag' => [['name' => 'tlp:clear']],
                ],
            ]], 1234);
        };
        $reply = $this->runner->run('SELECT ID, org, tags, nope FROM events WHERE id = 7');
        $this->assertSame(['id', 'Orgc.name', 'Tag', 'nope'], $reply['columns']);
        $this->assertSame(
            '[{"id":"7","Orgc.name":"CIRCL","Tag":["tlp:clear"],"nope":null}]',
            json_encode($reply['rows'])
        );
        $this->assertSame(['no row has a column nope'], $reply['warnings']);
        $this->assertSame(1234, $reply['total']);
        $this->assertSame(1, $this->backend->searches[0][1]['metadata']);
    }

    public function testFormatTableUsesTheDefaultColumns()
    {
        $this->backend->onSearch = function () {
            return self::reply(self::attributes(1, 1));
        };
        $reply = $this->runner->run('SELECT * FROM attributes LIMIT 1 FORMAT table');
        $this->assertSame('table', $reply['output']);
        $this->assertSame(
            ['id', 'event_id', 'category', 'type', 'value', 'to_ids', 'timestamp', 'Tag'],
            $reply['columns']
        );
        $this->assertSame([], $reply['warnings']);

        $reply = $this->runner->run('SELECT * FROM attributes LIMIT 1 FORMAT flat');
        $this->assertSame(['id', 'value', 'Tag'], $reply['columns']);
    }

    public function testAnOffsetWithinAPageReadsTheNextPageWhenTheFirstIsFull()
    {
        $this->backend->onSearch = function ($table, $body) {
            return self::reply($body['page'] === 2 ? self::attributes(11, 20) : self::attributes(21, 23));
        };
        $reply = $this->runner->run('SELECT id FROM attributes LIMIT 10 OFFSET 15');

        $this->assertSame([2, 3], array_column(array_column($this->backend->searches, 1), 'page'));
        $this->assertSame(
            ['16', '17', '18', '19', '20', '21', '22', '23'],
            array_column(json_decode(json_encode($reply['rows']), true), 'id')
        );

        $this->backend->searches = [];
        $this->backend->onSearch = function () {
            return self::reply(self::attributes(11, 17));
        };
        $reply = $this->runner->run('SELECT id FROM attributes LIMIT 10 OFFSET 15');
        $this->assertCount(1, $this->backend->searches);
        $this->assertCount(2, $reply['rows']);
    }

    public function testCounts()
    {
        $this->backend->onSearch = function ($table) {
            return $table === 'events' ? self::reply(['response' => []], 42) : self::reply(" 17\n", 1);
        };
        $this->assertSame(42, $this->runner->run('SELECT COUNT(*) FROM events WHERE id > 0')['count']);
        $reply = $this->runner->run('SELECT COUNT(*) FROM tags WHERE id > 0');
        $this->assertSame(['count', 17], [$reply['kind'], $reply['count']]);
        $this->assertSame(['returnFormat' => 'count', 'query' => ['id' => ['>' => 0]]], $reply['request']['body']);

        $this->backend->onSearch = function () {
            return self::reply('{"response": []}');
        };
        $this->expectException(UnexpectedValueException::class);
        $this->runner->run('SELECT COUNT(*) FROM tags WHERE id > 0');
    }

    public function testMispFormatsComeBackForRestSearchToSend()
    {
        $this->backend->onSearch = function () {
            return ['result' => 'id,value', 'count' => 1, 'filters' => []];
        };
        $reply = $this->runner->run('SELECT * FROM attributes LIMIT 1 FORMAT csv');
        $this->assertSame(['export', 'Attribute'], [$reply['kind'], $reply['scope']]);
        $this->assertSame('id,value', $reply['run']['result']);
        $this->assertSame('csv', $this->backend->searches[0][1]['returnFormat']);
    }

    public function testATreeErrorFromTheSearchIsPlaced()
    {
        $this->backend->onSearch = function () {
            throw new ComplexQueryException([['path' => 'query', 'code' => 'bad_type', 'message' => 'm']]);
        };
        $errors = $this->refused(function () {
            $this->runner->run('SELECT * FROM tags WHERE id = 1');
        });
        $this->assertSame(
            [0, 25, 31, 'query'],
            [$errors[0]['statement'], $errors[0]['start'], $errors[0]['end'], $errors[0]['path']]
        );
    }

    public function testNothingRunsWhenTheTreeIsRefused()
    {
        $this->backend->onValidate = function () {
            throw new ComplexQueryException([['path' => 'query', 'code' => 'bad_type', 'message' => 'm']]);
        };
        $this->refused(function () {
            $this->runner->run('SELECT * FROM tags WHERE id = 1');
        });
        $this->assertSame([], $this->backend->searches);
    }

    public function testTheRoleLimitIsReportedWhenItEndsThePage()
    {
        $this->backend->onSearch = function () {
            return self::reply(self::attributes(1, 3), 4, 3);
        };
        $warnings = $this->runner->run("SELECT id FROM attributes WHERE type = 'x'")['warnings'];
        $this->assertSame(["the role's restSearch limit stopped this search at 3 rows"], $warnings);
        $this->assertCount(1, $this->runner->run('SELECT id FROM attributes LIMIT 50')['warnings']);
        $this->assertSame([], $this->runner->run('SELECT id FROM attributes LIMIT 3')['warnings']);

        $this->backend->onSearch = function () {
            return self::reply(self::attributes(1, 2), 2, 3);
        };
        $this->assertSame([], $this->runner->run("SELECT id FROM attributes WHERE type = 'x'")['warnings']);
    }

    public function testDescribeShowTablesAndWhoami()
    {
        $reply = $this->decoded($this->runner->run('DESCRIBE events'));
        $this->assertSame(['describe', 'events'], [$reply['kind'], $reply['table']]);
        $this->assertSame(['id'], array_keys($reply['fields']));
        $this->assertContains('eventinfo', $reply['order_by']);
        $this->assertNotContains('info', $reply['order_by']);
        $this->assertSame(['max_depth' => 5], $reply['limits']);

        $this->assertSame(['attributes', 'tags'], $this->runner->run('SHOW TABLES')['tables']);
        $this->assertSame(
            [
                'language' => '1.0', 'kind' => 'whoami',
                'email' => 'admin@example.test', 'role' => 'admin', 'org' => 'ORGNAME',
            ],
            $this->runner->run('WHOAMI')
        );
    }
}
