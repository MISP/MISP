<?php
/**
 * ValueConditionRewriter against an in-memory dictionary: the shapes it
 * emits for the generic_add_filter forms, and a sweep that runs every
 * condition on the text columns and its rewrite on the ids, row by row, in
 * SQL's three-valued logic.
 *
 * ValueConditionRewriterDbTest runs the rewrites against the database.
 */

require_once __DIR__ . '/MigrationSchemaStubs.php';

use PHPUnit\Framework\TestCase;

class ValueConditionRewriterTest extends TestCase
{
    const ROWS = [
        ['evil.com', ''],
        ['EVIL.COM', ''],
        ['evil.com ', ''],
        ['Evil.com', '80'],
        ['a|b', ''],
        ['a', 'b'],
        ['a|b', 'c'],
        ['1.2.3.4', ' '],
        ['foo_bar', 'baz'],
        ['', ''],
        ['x', 'evil.com'],
        ['%literal', ''],
        ['back\\slash', ''],
    ];

    const TERMS = [
        'evil.com', 'EVIL.com', 'evil.com ', 'a|b', 'a|b|c', 'a', 'b', 'c', '', ' ', '80', 'Evil.com|80',
        'evil.com|80 ', 'nothing', '1.2.3.4', '1.2.3.4| ', 'x|', 'foo_bar|baz', 'x|evil.com', '%literal', 7,
    ];

    const PATTERNS = [
        '%evil%', 'evil%', '%80', '%', '%%', '', 'a|b%', '%a_b%', '%|%', '\\%%', 'a\\|b', '%.com|8%', '_',
        '%o_b%', 'evil.com', '%a%b%', 'back\\\\slash', '% ', '1.2.3.4|_', '1.2.3.4_%', 'a_b', '%|', '|%',
    ];

    /** @var FakeValueDictionary */
    private $dictionary;

    /** @var array[] */
    private $rows = [];

    protected function setUp(): void
    {
        require_once __DIR__ . '/ValueConditionRewriterSupport.php';
        $this->dictionary = new FakeValueDictionary();
        $this->rows = [];
        foreach (self::ROWS as $row) {
            $this->rows[] = [
                'value1' => $row[0],
                'value2' => $row[1],
                'value1_id' => $this->dictionary->add($row[0]),
                'value2_id' => $row[1] === '' ? null : $this->dictionary->add($row[1]),
            ];
        }
        $this->dictionary->add('unused');
    }

    private function rewriter(array $options = [], $alias = 'Attribute')
    {
        return new ValueConditionRewriter($this->dictionary, $alias, $options + ['strict' => true]);
    }

    private function ids(...$values)
    {
        $ids = [];
        foreach ($values as $value) {
            $ids[] = array_search($value, $this->dictionary->values, true);
        }
        sort($ids);
        return $ids;
    }

    public function testTheExactValueFilterBecomesTwoIdLists()
    {
        $conditions = ['AND' => [['OR' => ['OR' => [
            'Attribute.value1 IN' => ['evil.com'],
            'Attribute.value2 IN' => ['evil.com'],
        ]]]]];

        $rewritten = $this->rewriter()->rewrite($conditions);

        $ids = $this->ids('evil.com', 'EVIL.COM', 'evil.com ', 'Evil.com');
        $this->assertSame(['AND' => [['OR' => ['OR' => [
            ['Attribute.value1_id IN' => $ids],
            ['Attribute.value2_id IN' => $ids],
        ]]]]], $rewritten);
        $this->assertSame([['evil.com']], $this->dictionary->calls['resolveCi']);
        $this->assertSame([], $this->dictionary->calls['resolveLike']);
    }

    public function testNegationKeepsTheRowsWithoutAValue2()
    {
        $conditions = ['AND' => [['AND' => [
            'Attribute.value1 !=' => ['evil.com'],
            'Attribute.value2 !=' => ['evil.com'],
        ]]]];

        $rewritten = $this->rewriter()->rewrite($conditions);

        $ids = $this->ids('evil.com', 'EVIL.COM', 'evil.com ', 'Evil.com');
        $this->assertSame(['AND' => [['AND' => [
            ['Attribute.value1_id NOT IN' => $ids],
            ['OR' => [['Attribute.value2_id' => null], ['Attribute.value2_id NOT IN' => $ids]]],
        ]]]], $rewritten);
    }

    public function testAnEmptyValue2TermMatchesTheRowsWithoutOne()
    {
        $rewritten = $this->rewriter()->rewrite(['Attribute.value2' => '']);

        $this->assertSame([['OR' => [['Attribute.value2_id' => null], ['Attribute.value2_id IN' => $this->ids('', ' ')]]]], $rewritten);
    }

    public function testAWildcardTermGivesLikeAndEquality()
    {
        $conditions = ['AND' => [['OR' => [
            ['Attribute.value1 LIKE' => '%evil%'],
            ['Attribute.value1' => '%evil%'],
            ['Attribute.value2 LIKE' => '%evil%'],
            ['Attribute.value2' => '%evil%'],
        ]]]];

        $rewritten = $this->rewriter()->rewrite($conditions);

        $ids = $this->ids('evil.com', 'EVIL.COM', 'evil.com ', 'Evil.com');
        $this->assertSame(['AND' => [['OR' => [
            [['Attribute.value1_id IN' => $ids]],
            [ValueConditionRewriter::SQL_FALSE],
            [['Attribute.value2_id IN' => $ids]],
            [ValueConditionRewriter::SQL_FALSE],
        ]]]], $rewritten);
        $this->assertSame([['%evil%', ValueConditionRewriter::OVERFLOW]], $this->dictionary->calls['resolveLike']);
    }

    public function testAnOverflowingPatternReadsTheDictionaryInsideTheStatement()
    {
        $rewritten = $this->rewriter(['overflow' => 2])->rewrite([
            'Attribute.value1 LIKE' => '%evil%',
            'Attribute.value2 NOT LIKE' => '%evil%',
        ]);

        $this->assertCount(2, $rewritten);
        $this->assertSame('Attribute.value1_id IN (LIKE %evil%)', $rewritten[0][0]->value);
        $this->assertSame(['Attribute.value2_id' => null], $rewritten[1]['OR'][0]);
        $this->assertSame('Attribute.value2_id NOT IN (LIKE %evil%)', $rewritten[1]['OR'][1][0]->value);
        $this->assertCount(1, $this->dictionary->calls['resolveLike']);
    }

    public function testABoundedFindReadsUnanchoredPatternsInsideTheStatement()
    {
        foreach ([['Attribute.event_id' => 3], ['AND' => ['Attribute.id IN' => [1, 2]]], [['object_id' => 9]]] as $bound) {
            $this->dictionary->calls['resolveLike'] = [];

            $rewritten = $this->rewriter()->rewrite(array_merge($bound, ['Attribute.value1 LIKE' => '%evil%', 'Attribute.value2 LIKE' => 'evil%']));

            $expressions = [];
            array_walk_recursive($rewritten, function ($item) use (&$expressions) {
                if (is_object($item)) {
                    $expressions[] = $item->value;
                }
            });
            $this->assertSame(['Attribute.value1_id IN (LIKE %evil%)'], $expressions);
            $this->assertSame([['evil%', ValueConditionRewriter::OVERFLOW]], $this->dictionary->calls['resolveLike']);
        }
    }

    public function testOnlyATopLevelFewIdsBoundTheFind()
    {
        $unbounded = [
            ['OR' => ['Attribute.event_id' => 3]],
            ['Attribute.event_id' => range(1, ValueConditionRewriter::BOUND + 1)],
            ['Attribute.event_id >' => 3],
            ['Event.id' => 3],
            ['NOT' => ['Attribute.id' => 3]],
        ];
        foreach ($unbounded as $conditions) {
            $this->dictionary->calls['resolveLike'] = [];

            $this->rewriter()->rewrite($conditions + ['Attribute.value1 LIKE' => '%evil%']);

            $this->assertCount(1, $this->dictionary->calls['resolveLike'], json_encode($conditions));
        }
    }

    public function testACompositeTermOnTheValueFieldTriesBothReadings()
    {
        $rewritten = $this->rewriter()->rewrite(['Attribute.value' => 'a|b']);

        $blank = $this->ids('', ' ');
        $this->assertSame([['OR' => [
            [
                ['OR' => [['Attribute.value2_id' => null], ['Attribute.value2_id IN' => $blank]]],
                ['Attribute.value1_id IN' => $this->ids('a|b')],
            ],
            [
                ['Attribute.value2_id !=' => null],
                ['Attribute.value2_id NOT IN' => $blank],
                ['Attribute.value1_id IN' => $this->ids('a')],
                ['Attribute.value2_id IN' => $this->ids('b')],
            ],
        ]]], $rewritten);
    }

    public function testATermWithoutAPipeOnTheValueFieldReadsValue1OfRowsWithoutAValue2()
    {
        unset($this->dictionary->values[array_search(' ', $this->dictionary->values, true)]);
        unset($this->dictionary->values[array_search('', $this->dictionary->values, true)]);

        $rewritten = $this->rewriter()->rewrite(['value' => 'evil.com']);

        $this->assertSame([[
            ['Attribute.value2_id' => null],
            ['Attribute.value1_id IN' => $this->ids('evil.com', 'EVIL.COM', 'evil.com ', 'Evil.com')],
        ]], $rewritten);
    }

    public function testTermsAreResolvedOnceForAllLeaves()
    {
        $this->rewriter()->rewrite([
            'OR' => [
                'Attribute.value1' => ['a', 'b'],
                'Attribute.value2' => ['b', 'a'],
                'Attribute.value' => 'a',
            ],
        ]);

        $this->assertSame([['a', 'b'], ['']], $this->dictionary->calls['resolveCi']);
    }

    public function testTheResultsOfOneRewriteAreNotReusedByTheNext()
    {
        $rewriter = $this->rewriter();
        $rewriter->rewrite(['Attribute.value1' => 'a']);
        $added = $this->dictionary->add('A ');

        $rewritten = $rewriter->rewrite(['Attribute.value1' => 'a']);

        $this->assertContains($added, $rewritten[0]['Attribute.value1_id IN']);
    }

    public function testNullAndEmptyFormsKeepTheirMeaning()
    {
        $rewriter = $this->rewriter();
        $false = ValueConditionRewriter::SQL_FALSE;
        $true = ValueConditionRewriter::SQL_TRUE;

        $this->assertSame([$false], $rewriter->rewrite(['Attribute.value1' => null]));
        $this->assertSame([$false], $rewriter->rewrite(['Attribute.value2' => []]));
        $this->assertSame([$true], $rewriter->rewrite(['Attribute.value2 !=' => null]));
        $this->assertSame([$true], $rewriter->rewrite(['Attribute.value1 !=' => []]));
        $this->assertSame([$false], $rewriter->rewrite(['Attribute.value1 NOT IN' => ['a', null]]));
        $this->assertSame([['Attribute.value1_id IN' => $this->ids('a')]], $rewriter->rewrite(['Attribute.value1' => ['a', null]]));
        $this->assertSame([$false], $rewriter->rewrite(['Attribute.value1' => 'nothing']));
        $this->assertSame([$true], $rewriter->rewrite(['Attribute.value1 LIKE' => '%']));
        $this->assertSame([$true], $rewriter->rewrite(['Attribute.value2 LIKE' => '%%']));
        $this->assertSame([$false], $rewriter->rewrite(['Attribute.value2 NOT LIKE' => '%']));
    }

    public function testOtherConditionsAreLeftAlone()
    {
        $conditions = [
            'Attribute.event_id' => 3,
            'Attribute.comment LIKE' => '%value1%',
            'GalaxyCluster.value' => 'x',
            'Attribute.value1_id' => [1, 2],
            "Attribute.comment = 'Attribute.value1'",
            'OR' => ['Attribute.deleted' => 0, 'Attribute.type' => 'value2'],
        ];

        $this->assertSame($conditions, $this->rewriter()->rewrite($conditions));
        $this->assertSame('Attribute.deleted = 0', $this->rewriter()->rewrite('Attribute.deleted = 0'));
        $this->assertNull($this->rewriter()->rewrite(null));
        $this->assertSame([], $this->dictionary->calls['resolveCi']);
    }

    public function testARewriteIsLeftAsItIsByAnotherRewrite()
    {
        $conditions = [
            'Attribute.event_id' => 3,
            'Attribute.value LIKE' => '%evil%',
            'NOT' => ['Attribute.value' => ['a|b', 'x']],
            'Attribute.value2 LIKE' => 'evil%',
        ];
        $rewriter = $this->rewriter(['overflow' => 1]);
        $once = $rewriter->rewrite($conditions);

        $this->assertEquals($once, $rewriter->rewrite($once));
    }

    public function testStrictModeRefusesWhatItCannotCarryOver()
    {
        $refused = [
            ['LOWER(Attribute.value1) LIKE' => '%x%'],
            ["CONCAT(Attribute.value1, '|', Attribute.value2)" => 'a|b'],
            ['INET_ATON(value1) BETWEEN ? AND ?' => [1, 2]],
            ['IS_IPV6(value1)'],
            ['OR' => ['Attribute.value1 = 1']],
            ['ShadowAttribute.value1' => 'x'],
            ['Attribute.value1 >' => 'x'],
            ['Attribute.value1 IN' => 'x'],
            ['Attribute.value1 NOT IN' => []],
            ['Attribute.value LIKE' => ['a']],
            ['Attribute.value1' => ['x' => 'y']],
            ['Attribute.value1' => [0 => 'a', 2 => 'b']],
            ['Attribute.value1' => true],
            ['Attribute.Value1' => 'x'],
            "Attribute.value1 = 'x'",
        ];
        foreach ($refused as $conditions) {
            try {
                $this->rewriter()->rewrite($conditions);
                $this->fail('Not refused: ' . json_encode($conditions));
            } catch (ValueConditionException $e) {
                $this->assertStringContainsString('Attribute value columns', $e->getMessage());
            }
        }
    }

    public function testOutsideStrictModeAnUnknownFormIsReportedAndPassedThrough()
    {
        $rewriter = new ReportingValueConditionRewriter($this->dictionary, 'Attribute', ['strict' => false]);
        $conditions = ['LOWER(Attribute.value1) LIKE' => '%x%', 'Attribute.value1' => 'a', 'IS_IPV6(value1)'];

        $rewritten = $rewriter->rewrite($conditions);

        $this->assertSame([
            'LOWER(Attribute.value1) LIKE' => '%x%',
            ['Attribute.value1_id IN' => $this->ids('a')],
            'IS_IPV6(value1)',
        ], $rewritten);
        $this->assertCount(2, $rewriter->reports);
    }

    public function testStrictModeFollowsTheDebugLevel()
    {
        $debug = Configure::read('debug');
        try {
            Configure::write('debug', 0);
            $relaxed = new ReportingValueConditionRewriter($this->dictionary, 'Attribute');
            $relaxed->rewrite(['IS_IPV6(value1)']);
            $this->assertCount(1, $relaxed->reports);

            Configure::write('debug', 1);
            $strict = new ReportingValueConditionRewriter($this->dictionary, 'Attribute');
            try {
                $strict->rewrite(['IS_IPV6(value1)']);
                $this->fail('Debug mode is strict.');
            } catch (ValueConditionException $e) {
                $this->assertSame([], $strict->reports);
            }
        } finally {
            Configure::write('debug', $debug);
        }
    }

    public function testTheProposalAliasIsItsOwn()
    {
        $rewritten = $this->rewriter([], 'ShadowAttribute')->rewrite(['ShadowAttribute.value1' => 'a', 'value2' => 'b']);

        $this->assertSame([
            ['ShadowAttribute.value1_id IN' => $this->ids('a')],
            ['ShadowAttribute.value2_id IN' => $this->ids('b')],
        ], $rewritten);

        $this->expectException(ValueConditionException::class);
        $this->rewriter([], 'ShadowAttribute')->rewrite(['Attribute.value' => 'a']);
    }

    public function testEveryFormMatchesTheRowsThe2xColumnsMatched()
    {
        $mismatches = [];
        foreach ($this->leaves() as $leaf) {
            foreach ($this->contexts($leaf) as $conditions) {
                foreach ([[], ['overflow' => 1], ['bounded' => true], ['bounded' => true, 'overflow' => 1]] as $mode) {
                    $mismatches = array_merge($mismatches, $this->compare($conditions, $mode));
                }
            }
        }
        $this->assertSame([], array_slice($mismatches, 0, 20), count($mismatches) . ' mismatches');
    }

    public function testThePatternSplitsAreExercised()
    {
        $this->rewriter()->rewrite(['Attribute.value LIKE' => '%a_b|c%']);

        $patterns = array_column($this->dictionary->calls['resolveLike'], 0);
        sort($patterns);
        $this->assertSame(['%a', '%a_b', '%a_b|c%', 'b|c%', 'c%'], $patterns);
    }

    private function leaves()
    {
        $leaves = [];
        foreach (['value', 'value1', 'value2'] as $column) {
            $key = 'Attribute.' . $column;
            foreach (self::TERMS as $term) {
                $leaves[] = [$key => $term];
                $leaves[] = [$key . ' !=' => $term];
            }
            foreach (array_chunk(self::TERMS, 3) as $chunk) {
                $leaves[] = [$key . ' IN' => $chunk];
                $leaves[] = [$key . ' NOT IN' => $chunk];
                $leaves[] = [$key => $chunk];
                $leaves[] = [$key . ' !=' => $chunk];
            }
            foreach (self::PATTERNS as $pattern) {
                $leaves[] = [$key . ' LIKE' => $pattern];
                $leaves[] = [$key . ' NOT LIKE' => $pattern];
            }
        }
        return $leaves;
    }

    private function contexts(array $leaf)
    {
        return [
            $leaf,
            ['NOT' => $leaf],
            ['OR' => [$leaf, ['Attribute.value1' => 'nothing']]],
            ['NOT' => ['OR' => [$leaf, ['Attribute.value2 LIKE' => 'evil%']]]],
            ['XOR' => [$leaf, ['Attribute.value' => 'a']]],
        ];
    }

    private function compare(array $conditions, array $mode)
    {
        $bounded = !empty($mode['bounded']);
        unset($mode['bounded']);
        if ($bounded) {
            $conditions = ['Attribute.event_id' => 1, $conditions];
        }
        $rewritten = $this->rewriter($mode)->rewrite($conditions);
        $evaluator = new ValueConditionEvaluator($this->dictionary, 'Attribute');
        $mismatches = [];
        foreach ($this->rows as $row) {
            $expected = $evaluator->evaluate($conditions, $row, false) === true;
            $actual = $evaluator->evaluate($rewritten, $row, true) === true;
            if ($expected !== $actual) {
                $mismatches[] = sprintf(
                    '%s %s on %s|%s: 2.x %s, ids %s',
                    json_encode($conditions),
                    json_encode($mode),
                    $row['value1'],
                    $row['value2'],
                    var_export($expected, true),
                    var_export($actual, true)
                );
            }
        }
        return $mismatches;
    }
}
