<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Vendor/autoload.php';

if (!function_exists('__')) {
    // Fake translation function
    function __($singular, $args = null)
    {
        $arguments = func_get_args();
        return vsprintf($singular, array_slice($arguments, 1));
    }
}

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package = null)
        {
        }
    }
}

// The real Hash, not a stand-in: _dataToCsv's tabular branch depends on
// Hash::flatten leaving empty arrays in place, which is what used to reach
// strval() as the literal string "Array".
if (!class_exists('Hash', false)) {
    require_once __DIR__ . '/../Lib/cakephp/lib/Cake/Utility/Hash.php';
}

if (!class_exists('AppController', false)) {
    class AppController
    {
    }
}

require_once __DIR__ . '/../Controller/DashboardsController.php';

/**
 * V15 - the widget CSV export (`renderWidget/<id>/exportcsv:1`) is a
 * hand-rolled writer whose fields are attacker-reachable: widgets key
 * their payload on tag names (TrendingTagsWidget) and on raw
 * Attribute.value1 (TrendingAttributesWidget).
 *
 * Two properties are asserted here:
 *
 *  1. Structure. A value carrying a comma, a double quote or a newline
 *     must not change the field count of its row, in either branch.
 *  2. Fidelity. Indicator values are emitted verbatim - no spreadsheet
 *     formula neutralisation (CWE-1236). MISP CSV is a machine-ingest
 *     format and prefixing `=` / `+` / `-` / `@` would corrupt the data
 *     for the tooling that consumes it.
 */
class DashboardCsvExportTest extends TestCase
{
    /**
     * @param array $data
     * @return string
     */
    private function toCsv(array $data)
    {
        $controller = (new ReflectionClass('DashboardsController'))->newInstanceWithoutConstructor();
        $method = new ReflectionMethod('DashboardsController', '_dataToCsv');
        $method->setAccessible(true);
        return $method->invoke($controller, $data);
    }

    /**
     * Parse emitted CSV back into a field matrix the way any consumer would.
     *
     * @param string $csv
     * @return array
     */
    private function parse($csv)
    {
        $handle = fopen('php://memory', 'r+');
        fwrite($handle, $csv);
        rewind($handle);
        $rows = array();
        while (($row = fgetcsv($handle)) !== false) {
            if ($row === array(null)) {
                continue;
            }
            $rows[] = $row;
        }
        fclose($handle);
        return $rows;
    }

    public function testAssociativeBranchQuotesKeysContainingDelimiters()
    {
        $rows = $this->parse($this->toCsv(array('data' => array(
            'plain' => 1,
            'has,comma' => 2,
            'has"quote' => 3,
            "has\nnewline" => 4,
        ))));
        $this->assertCount(4, $rows);
        foreach ($rows as $row) {
            $this->assertCount(2, $row, 'every row is exactly key,value');
        }
        $this->assertSame(
            array('plain', 'has,comma', 'has"quote', "has\nnewline"),
            array_column($rows, 0),
            'keys round-trip byte-exact through a CSV parser'
        );
    }

    public function testAssociativeBranchQuotesStructuredValues()
    {
        // json_encode of a multi-key array embeds a comma, which used to
        // split the row into a third column.
        $rows = $this->parse($this->toCsv(array('data' => array(
            'alpha' => array('x' => 1, 'y' => 2),
        ))));
        $this->assertCount(1, $rows);
        $this->assertCount(2, $rows[0]);
        $this->assertSame('{"x":1,"y":2}', $rows[0][1]);
    }

    public function testTabularBranchDoublesQuotesSoHeaderAndRowsStayAligned()
    {
        $rows = $this->parse($this->toCsv(array('data' => array(
            array('date' => '2026-01-01', 'tag"with,quote' => 1),
            array('date' => '2026-01-02', 'tag"with,quote' => 2),
        ))));
        $this->assertCount(3, $rows);
        $this->assertSame(count($rows[0]), count($rows[1]), 'header width matches row width');
        $this->assertSame(array('date', 'tag"with,quote'), $rows[0]);
    }

    public function testTabularBranchRendersEmptyArraysWithoutWarning()
    {
        // Hash::flatten keeps an empty array as a value; strval() turned it
        // into the literal "Array" and raised "Array to string conversion".
        $rows = $this->parse($this->toCsv(array('data' => array(
            array('nested' => array(), 'n' => 1),
            array('nested' => array(), 'n' => 2),
        ))));
        $this->assertSame(array('nested', 'n'), $rows[0]);
        $this->assertSame('[]', $rows[1][0]);
    }

    /**
     * The security-relevant negative: values are NOT mutated.
     */
    public function testFormulaPrefixesArePreservedVerbatim()
    {
        $payloads = array(
            '=HYPERLINK("http://attacker.example",A1)',
            '+1+1',
            '@SUM(A1)',
            '-7+8',
            '@WanaDecryptor@.exe',
            '=?UTF-8?Q?Le_colis?=',
        );
        $data = array();
        foreach ($payloads as $payload) {
            $data[$payload] = 1;
        }
        $rows = $this->parse($this->toCsv(array('data' => $data)));
        $this->assertSame($payloads, array_column($rows, 0));

        $tabular = $this->parse($this->toCsv(array('data' => array(
            array('value' => '=HYPERLINK("http://attacker.example",A1)'),
            array('value' => '@WanaDecryptor@.exe'),
        ))));
        $this->assertSame('=HYPERLINK("http://attacker.example",A1)', $tabular[1][0]);
        $this->assertSame('@WanaDecryptor@.exe', $tabular[2][0]);
    }

    /**
     * Anything that already parsed correctly keeps the bytes v1 emitted.
     */
    public function testCleanPayloadsAreByteIdenticalToTheLegacyWriter()
    {
        $this->assertSame(
            'alpha,3' . PHP_EOL . 'beta,1' . PHP_EOL,
            $this->toCsv(array('data' => array('alpha' => 3, 'beta' => 1)))
        );
        $this->assertSame(
            'a,true' . PHP_EOL . 'b,false' . PHP_EOL . 'c,null' . PHP_EOL,
            $this->toCsv(array('data' => array('a' => true, 'b' => false, 'c' => null)))
        );
        $this->assertSame(
            '"date","n"' . PHP_EOL . '"2026-01-01","1"' . PHP_EOL,
            $this->toCsv(array('data' => array(array('date' => '2026-01-01', 'n' => 1))))
        );
        // strval() semantics for booleans in the tabular branch: true is "1",
        // false is the empty string. Preserved deliberately.
        $this->assertSame(
            '"p","q"' . PHP_EOL . '"","1"' . PHP_EOL,
            $this->toCsv(array('data' => array(array('p' => false, 'q' => true))))
        );
    }

    public function testEmptyPayloadYieldsEmptyString()
    {
        $this->assertSame('', $this->toCsv(array()));
        // Pre-existing quirk, deliberately preserved: the `!empty($data['data'])`
        // guard treats an empty `data` key as "no wrapper", so the wrapper itself
        // falls through to the associative branch and emits a junk row. The
        // legacy writer did exactly the same; changing it is not part of V15.
        $this->assertSame('data,[]' . PHP_EOL, $this->toCsv(array('data' => array())));
    }
}
