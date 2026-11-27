<?php
/**
 * MispQL 1.0 as pinned by the cases in app/Test/MispQL (see its README):
 * compile plans, errors, server error paths placed on the text, and what
 * happens to MISP's rows. Pure PHPUnit, no database.
 */
require_once __DIR__ . '/MispQLFixtures.php';

use PHPUnit\Framework\TestCase;

class MispQLConformanceTest extends TestCase
{
    const SUITE = __DIR__ . '/MispQL';

    private static function decode($file, $assoc = true)
    {
        return json_decode(file_get_contents($file), $assoc, 512, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
    }

    public function testLanguageVersion()
    {
        $this->assertSame(MispQLCompiler::LANGUAGE, trim(file_get_contents(self::SUITE . '/VERSION')));
    }

    public function compileCases()
    {
        $cases = [];
        foreach (glob(self::SUITE . '/compile/*.mql') as $mql) {
            $cases[basename($mql, '.mql')] = [$mql, substr($mql, 0, -4) . '.json'];
        }
        return $cases;
    }

    /**
     * @dataProvider compileCases
     */
    public function testCompile($mql, $json)
    {
        $text = file_get_contents($mql);
        $expected = self::decode($json)['statements'];
        foreach ($expected as $statement) {
            foreach ($statement['spans'] as $path => $span) {
                $this->assertSame(
                    $span['fragment'],
                    MispQLLexer::slice($text, $span['start'], $span['end']),
                    "offsets of $path are not code points"
                );
            }
        }
        $actual = [];
        foreach (MispQLFixtures::compiler()->compileScript($text) as $plan) {
            $actual[] = MispQLFixtures::withFragments($plan, $text);
        }
        $this->assertSame($expected, $actual);
    }

    public function errorCases()
    {
        $cases = [];
        foreach (self::decode(self::SUITE . '/errors.json') as $i => $case) {
            $cases["$i {$case['source']}"] = [$case];
        }
        return $cases;
    }

    /**
     * @dataProvider errorCases
     */
    public function testError(array $case)
    {
        $text = $case['statement'];
        $this->assertSame($case['fragment'], MispQLLexer::slice($text, $case['start'], $case['end']));
        try {
            MispQLFixtures::compiler()->compileScript($text);
        } catch (MispQLException $e) {
            $this->assertSame(
                [$case['code'], $case['start'], $case['end']],
                [$e->getErrorCode(), $e->getStart(), $e->getEnd()],
                $e->getMessage()
            );
            $this->assertSame($case['fragment'], MispQLLexer::slice($text, $e->getStart(), $e->getEnd()));
            return;
        }
        $this->fail('the statement compiled');
    }

    public function serverErrorCases()
    {
        $cases = [];
        foreach (glob(self::SUITE . '/server_errors/*.json') as $file) {
            $cases[basename($file, '.json')] = [self::decode($file)];
        }
        return $cases;
    }

    /**
     * @dataProvider serverErrorCases
     */
    public function testServerErrorPaths(array $case)
    {
        $plans = MispQLFixtures::compiler()->compileScript($case['statement']);
        $this->assertCount(1, $plans);
        $plan = $plans[0];
        $this->assertSame($case['body'], $plan['body']);
        $located = [];
        foreach ($case['reply']['errors'] as $error) {
            $span = MispQLCompiler::locate($plan['spans'], $error['path']) ?? [$plan['start'], $plan['end']];
            $located[$error['path']] = MispQLFixtures::located($span, $case['statement']);
        }
        $this->assertSame($case['located'], $located);
    }

    public function locateCases()
    {
        $cases = [];
        foreach (self::decode(self::SUITE . '/locate.json') as $i => $case) {
            $cases["$i {$case['path']}"] = [$case];
        }
        return $cases;
    }

    /**
     * @dataProvider locateCases
     */
    public function testLocate(array $case)
    {
        $plans = MispQLFixtures::compiler()->compileScript($case['statement']);
        $this->assertCount(1, $plans);
        $span = MispQLCompiler::locate($plans[0]['spans'], $case['path']);
        $this->assertSame(
            $case['located'],
            $span === null ? null : MispQLFixtures::located($span, $case['statement'])
        );
    }

    public function rowsCases()
    {
        $cases = [];
        foreach (glob(self::SUITE . '/rows/*.json') as $file) {
            $cases[basename($file, '.json')] = [$file];
        }
        return $cases;
    }

    /**
     * The keys present in a case are the steps it checks.
     *
     * @dataProvider rowsCases
     */
    public function testRows($file)
    {
        $case = self::decode($file, false);
        $tables = MispQLFixtures::tables();
        $plan = null;
        if (isset($case->statement)) {
            $plans = MispQLFixtures::compiler()->compileScript($case->statement);
            $this->assertCount(1, $plans);
            $plan = $plans[0];
        }
        $steps = 0;
        if (property_exists($case, 'reply')) {
            $rows = MispQLRows::unwrap($case->reply, $tables->get($plan['table'])['rowKey']);
            $this->assertSame(self::canon($case->rows), self::canon($rows), 'unwrapping');
            $steps++;
        }
        if (property_exists($case, 'rows') && property_exists($case, 'flat')) {
            $flat = array_map([MispQLRows::class, 'flatten'], $case->rows);
            $this->assertSame(self::canon($case->flat), self::canon($flat), 'flattening');
            $steps++;
        }
        if (property_exists($case, 'flat') && property_exists($case, 'columns')) {
            list($columns, $cells, $warnings) = MispQLRows::project(
                $plan,
                $case->flat,
                $tables->get($plan['table'])['columns']
            );
            $this->assertSame(self::canon($case->columns), self::canon($columns), 'columns');
            $this->assertSame(self::canon($case->cells), self::canon($cells), 'cells');
            $this->assertSame(self::canon($case->warnings), self::canon($warnings), 'warnings');
            $steps++;
        }
        $this->assertGreaterThan(0, $steps, 'the case checks no step');
    }

    /**
     * Decoded JSON in a form assertSame() compares strictly: objects keep
     * their key order and stay apart from lists.
     */
    private static function canon($value)
    {
        if (is_object($value)) {
            $pairs = [];
            foreach ($value as $key => $item) {
                $pairs[] = [(string)$key, self::canon($item)];
            }
            return ['{}' => $pairs];
        }
        if (is_array($value)) {
            return ['[]' => array_map([self::class, 'canon'], $value)];
        }
        return $value;
    }
}
