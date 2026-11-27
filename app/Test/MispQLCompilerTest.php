<?php
/**
 * MispQL behaviour the shared cases in app/Test/MispQL do not pin: the length
 * cap, edge cases PHP is prone to get wrong, MISP's own messages, and the
 * sort names read from the models. Pure PHPUnit, no database.
 */
require_once __DIR__ . '/MispQLFixtures.php';

use PHPUnit\Framework\TestCase;

class MispQLCompilerTest extends TestCase
{
    const MESSAGES = [
        'COUNT(*) needs a WHERE',
        'COUNT(*) takes no FORMAT',
        'COUNT(*) takes no LIMIT',
        'COUNT(*) takes no OFFSET',
        'COUNT(*) takes no ORDER BY',
        'LIMIT must be at least 1',
        'OFFSET must be a multiple of LIMIT with a format MISP exports',
        'OFFSET needs a LIMIT',
        'OFFSET too large for this LIMIT',
        'a column list needs FORMAT table, FORMAT flat or no FORMAT; other formats are sent as MISP exports them',
        'a word starting with a digit must be quoted',
        'add a WHERE or a LIMIT: MISP takes no search without either',
        'empty name',
        "expected ')'",
        "expected '*' (COUNT takes only *)",
        "expected ',' or ')'",
        "expected ';'",
        'expected *, COUNT(*) or field names',
        "expected AND, OR, ORDER BY, LIMIT, OFFSET, FORMAT or ';'",
        'expected BY',
        'expected IN or LIKE after NOT',
        "expected OFFSET, FORMAT or ';'",
        'expected SELECT, DESCRIBE, SHOW, USE or WHOAMI',
        'expected TABLES or DATABASES',
        "expected a 'quoted pattern' after LIKE",
        'expected a database name',
        'expected a database name; quote it with backticks to use it as a name',
        'expected a field name',
        'expected a format name',
        'expected a table name',
        'expected a table name; quote it with backticks to use it as a name',
        "expected a value ('string', number, TRUE or FALSE)",
        "expected a value ('string', number, TRUE or FALSE); strings need quotes",
        'expected a whole number after LIMIT',
        'expected an operator (=, !=, <, >, <=, >=, IN, NOT IN, LIKE, NOT LIKE)',
        'expected at least one value in IN (...)',
        'name not closed',
        'nested too deep: at most 64 levels of parentheses and NOT',
        'number too large: at most 9223372036854775807',
        'only whole numbers are supported',
        'string not closed',
        'this field is qualified with another table than the one queried',
        'this table cannot be sorted',
        'unexpected character',
        'unexpected character; use != or NOT',
        'unknown table; use attributes, events, objects, galaxy_clusters, event_reports, notes, opinions, '
            . 'relationships, collections, tags or organisations',
    ];

    private function compile($text)
    {
        return MispQLFixtures::compiler()->compileScript($text);
    }

    private function assertRefused($text, $code, $start, $end)
    {
        try {
            $this->compile($text);
        } catch (MispQLException $e) {
            $this->assertSame([$code, $start, $end], [$e->getErrorCode(), $e->getStart(), $e->getEnd()]);
            return $e;
        }
        $this->fail('the statement compiled');
    }

    public function testLengthIsCountedInCodePointsBeforeTheLexerRuns()
    {
        $prefix = 'SELECT * FROM tags LIMIT 1 --';
        $atCap = $prefix . str_repeat('é', MispQLLexer::MAX_LENGTH - strlen($prefix));
        $this->assertSame(MispQLLexer::MAX_LENGTH, MispQLLexer::codePoints($atCap));
        $this->assertSame('tags', $this->compile($atCap)[0]['table']);

        $this->assertRefused($atCap . 'é', 'limit_exceeded', 1048576, 1048577);
        // The cap wins over a lexer error anywhere in the text.
        $this->assertRefused('!' . str_repeat(' ', MispQLLexer::MAX_LENGTH + 9), 'limit_exceeded', 1048576, 1048586);
    }

    public function testCommentEndsAtLineFeedOnly()
    {
        foreach (["\r", "\u{2028}", "\u{85}", "\u{0B}"] as $separator) {
            $body = $this->compile("SELECT * FROM tags WHERE id = 1 -- x{$separator}LIMIT 1")[0]['body'];
            $this->assertSame(['returnFormat' => 'json', 'query' => ['id' => 1]], $body);
        }
        $body = $this->compile("SELECT * FROM tags WHERE id = 1 -- x\nLIMIT 1")[0]['body'];
        $this->assertSame(['returnFormat' => 'json', 'limit' => 1, 'page' => 1, 'query' => ['id' => 1]], $body);
    }

    public function testFormatWordsPhpWouldTakeForEmpty()
    {
        $plan = $this->compile("SELECT * FROM tags LIMIT 1 FORMAT '0'")[0];
        $this->assertSame('0', $plan['body']['returnFormat']);
        $this->assertSame('verbatim', $plan['output']);
        $this->assertRefused("SELECT id FROM tags LIMIT 1 FORMAT '0'", 'bad_clause', 35, 38);

        $plan = $this->compile("SELECT * FROM tags LIMIT 2 OFFSET 1 FORMAT ''")[0];
        $this->assertSame(['json', 'verbatim', 1], [$plan['body']['returnFormat'], $plan['output'], $plan['skip']]);
    }

    public function testAnyUnicodeDigitAfterAPointMakesADecimal()
    {
        // As Python's str.isdigit() decides, in mispql 1.x.
        foreach (['2', '²', '٣', '１', "\u{1FBF5}"] as $digit) {
            $this->assertRefused("SELECT * FROM tags WHERE id = 1.$digit LIMIT 1", 'syntax', 30, 32);
        }
        $this->assertRefused('SELECT * FROM tags WHERE id = 1.x LIMIT 1', 'syntax', 31, 32);
    }

    public function testTextThatIsNotUtf8()
    {
        $this->assertRefused("SELECT * FROM tags WHERE name = '\xC3' LIMIT 1", 'syntax', 0, 0);
    }

    public function testMessagesAreFixedTexts()
    {
        foreach (json_decode(file_get_contents(__DIR__ . '/MispQL/errors.json'), true) as $case) {
            try {
                $this->compile($case['statement']);
                $this->fail('compiled: ' . $case['statement']);
            } catch (MispQLException $e) {
                $message = $e->getMessage();
                $sortable = preg_match('/^cannot sort this table by that field; use [a-z_]+(, [a-z_]+)*$/', $message);
                $this->assertTrue(in_array($message, self::MESSAGES, true) || $sortable === 1, $message);
            }
        }
    }

    public function testSortNamesComeFromTheModels()
    {
        $identity = function (array $names) {
            return array_combine($names, $names);
        };
        $expected = [
            'attributes' => $identity([
                'id', 'event_id', 'object_id', 'type', 'category', 'value', 'distribution', 'timestamp',
                'object_relation',
            ]) + ['publish_timestamp' => 'Event.publish_timestamp'],
            'events' => [
                'id' => 'id', 'event_id' => 'id', 'eventinfo' => 'info', 'analysis' => 'analysis',
                'threat_level_id' => 'threat_level_id', 'distribution' => 'distribution',
                'timestamp' => 'timestamp', 'event_timestamp' => 'timestamp',
                'publish_timestamp' => 'publish_timestamp',
            ],
            'objects' => [],
            'galaxy_clusters' => $identity([
                'id', 'version', 'type', 'value', 'distribution', 'orgc_id', 'org_id', 'tag_name', 'galaxy_id',
            ]),
            'event_reports' => $identity(['id', 'event_id', 'name', 'timestamp', 'distribution']),
            'notes' => $identity(['id', 'created', 'modified', 'distribution']),
            'opinions' => $identity(['id', 'created', 'modified', 'distribution', 'opinion']),
            'relationships' => $identity(['id', 'created', 'modified', 'distribution', 'relationship_type']),
            'collections' => $identity(['id', 'name', 'type', 'created', 'modified', 'distribution']),
            'tags' => $identity(['id', 'name', 'numerical_value']),
            'organisations' => $identity(['id', 'name', 'date_created', 'date_modified']),
        ];
        $tables = MispQLFixtures::tables();
        $this->assertSame(array_keys($expected), $tables->names());
        foreach ($expected as $name => $sortable) {
            $this->assertSame($sortable, $tables->sortable($name), $name);
        }
    }

    public function testEverySortAliasPointsAtAFieldItsModelSorts()
    {
        foreach (MispQLTables::TABLES as $name => $table) {
            if ($table['model'] === null) {
                $this->assertSame([], $table['sortAliases'] + $table['sortExcept'], $name);
                continue;
            }
            $serverNames = [];
            foreach (MispQLFixtures::orderFields($table['model']) as $model => $fields) {
                foreach ($fields as $field) {
                    $serverNames[] = $model === $table['modelAlias'] ? $field : "$model.$field";
                }
            }
            foreach ($table['sortAliases'] as $alias => $target) {
                $this->assertContains($target, $serverNames, "$name: $alias");
            }
            foreach ($table['sortExcept'] as $field) {
                $this->assertContains($field, $serverNames, "$name: $field");
            }
        }
    }
}
