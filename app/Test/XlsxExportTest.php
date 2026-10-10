<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Vendor/autoload.php';

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package = null)
        {
        }
    }
}

if (!class_exists('Hash', false)) {
    require_once __DIR__ . '/../Lib/cakephp/lib/Cake/Utility/Hash.php';
}

require_once __DIR__ . '/../Lib/Tools/TmpFileTool.php';
require_once __DIR__ . '/../Lib/Tools/XlsxWriterTool.php';
require_once __DIR__ . '/../Lib/Export/CsvExport.php';
require_once __DIR__ . '/../Lib/Export/XlsxExport.php';

class XlsxExportTest extends TestCase
{
    /**
     * Reads a workbook back into [sheetName => [[value, styleIndex], ...]].
     * Parses the parts directly so the assertions do not depend on a
     * spreadsheet library being present.
     */
    private function readWorkbook($binary)
    {
        $path = tempnam(sys_get_temp_dir(), 'xlsxtest');
        file_put_contents($path, $binary);
        $zip = new ZipArchive();
        $this->assertTrue($zip->open($path) === true, 'workbook is not a zip');

        $workbook = simplexml_load_string($zip->getFromName('xl/workbook.xml'));
        $this->assertNotFalse($workbook, 'xl/workbook.xml is not well formed');
        $names = [];
        foreach ($workbook->sheets->sheet as $sheet) {
            $names[] = (string)$sheet['name'];
        }

        $result = [];
        foreach ($names as $index => $name) {
            $xml = $zip->getFromName('xl/worksheets/sheet' . ($index + 1) . '.xml');
            $this->assertNotFalse($xml, "missing worksheet part for $name");
            $sheet = simplexml_load_string($xml);
            $this->assertNotFalse($sheet, "worksheet $name is not well formed");
            $rows = [];
            foreach ($sheet->sheetData->row as $row) {
                $cells = [];
                foreach ($row->c as $cell) {
                    $cells[] = [
                        'value' => isset($cell->is->t) ? (string)$cell->is->t : '',
                        'type' => isset($cell['t']) ? (string)$cell['t'] : '',
                        'style' => isset($cell['s']) ? (int)$cell['s'] : 0,
                        'formula' => isset($cell->f),
                    ];
                }
                $rows[] = $cells;
            }
            $result[$name] = $rows;
        }
        $zip->close();
        unlink($path);
        return $result;
    }

    private function values(array $rows)
    {
        return array_map(function ($row) {
            return array_column($row, 'value');
        }, $rows);
    }

    /**
     * Drives the export the way the restSearch drivers do.
     */
    private function export(array $attributes, array $filters = [])
    {
        $export = new XlsxExport();
        $options = ['scope' => 'Attribute', 'filters' => $filters];
        $export->header($options);
        foreach ($attributes as $attribute) {
            $this->assertSame('', $export->handler($attribute, $options));
        }
        return $this->readWorkbook((string)$export->footer($options));
    }

    private function attributeRow(array $overrides = [])
    {
        return ['Attribute' => $overrides + [
            'uuid' => 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
            'event_id' => '1',
            'category' => 'Network activity',
            'type' => 'ip-dst',
            'value' => '1.2.3.4',
            'comment' => '',
            'to_ids' => true,
            'timestamp' => '1600000000',
            'object_relation' => '',
        ], 'Event' => [
            'info' => 'test', 'distribution' => '0', 'threat_level_id' => '1',
            'analysis' => '0', 'date' => '2026-09-28', 'timestamp' => '1600000000',
            'Org' => ['name' => 'ORG'], 'Orgc' => ['name' => 'ORGC'],
        ]];
    }

    public function testHeaderMatchesTheCsvExport()
    {
        $csvOptions = ['scope' => 'Attribute', 'filters' => []];
        $csvHeader = trim((new CsvExport())->header($csvOptions));

        $sheets = $this->export([$this->attributeRow()]);
        $rows = $this->values(reset($sheets));
        $this->assertSame(explode(',', $csvHeader), $rows[0]);
    }

    public function testRowsMatchTheCsvExportValues()
    {
        $sheets = $this->export([$this->attributeRow(['value' => '9.9.9.9'])]);
        $rows = $this->values(reset($sheets));
        $this->assertCount(2, $rows);
        $this->assertContains('9.9.9.9', $rows[1]);
        $this->assertContains('ip-dst', $rows[1]);
        $this->assertContains('1', $rows[1], 'to_ids true is written as 1');
    }

    public function testHeaderlessOmitsTheHeaderRow()
    {
        $sheets = $this->export([$this->attributeRow()], ['headerless' => 1]);
        $rows = $this->values(reset($sheets));
        $this->assertCount(1, $rows);
        $this->assertContains('1.2.3.4', $rows[0]);
    }

    /**
     * A value ending in a backslash is what PHP's default fgetcsv escape
     * character destroys: the row would swallow the following columns.
     */
    public function testTrailingBackslashDoesNotSwallowTheRestOfTheRow()
    {
        $sheets = $this->export([
            $this->attributeRow(['value' => 'C:\\windows\\', 'comment' => 'next']),
        ]);
        $rows = $this->values(reset($sheets));
        $this->assertCount(count($rows[0]), $rows[1]);
        $this->assertContains('C:\\windows\\', $rows[1]);
        $this->assertContains('next', $rows[1]);
    }

    public function testCsvQuotingRoundTripsLosslessly()
    {
        $tricky = [
            'say "hi"',
            'a,b',
            "line1\nline2",
            'ünïcødé',
            '',
        ];
        $attributes = [];
        foreach ($tricky as $value) {
            $attributes[] = $this->attributeRow(['value' => $value]);
        }
        $sheets = $this->export($attributes);
        $rows = $this->values(reset($sheets));
        $valueColumn = array_search('value', $rows[0], true);
        $this->assertNotFalse($valueColumn);
        for ($i = 0; $i < count($tricky); $i++) {
            $this->assertSame($tricky[$i], $rows[$i + 1][$valueColumn]);
        }
    }

    public function testFormulaLeadsAreQuotePrefixedAndNeverBecomeFormulas()
    {
        $dangerous = ['=SUM(1)', "=cmd|'/c calc'!A1", '+41', '-5', '@x', "\tlead"];
        $attributes = [];
        foreach ($dangerous as $value) {
            $attributes[] = $this->attributeRow(['value' => $value]);
        }
        $sheets = $this->export($attributes);
        $rows = reset($sheets);
        $valueColumn = array_search('value', array_column($rows[0], 'value'), true);

        for ($i = 0; $i < count($dangerous); $i++) {
            $cell = $rows[$i + 1][$valueColumn];
            $this->assertSame(
                $dangerous[$i],
                $cell['value'],
                'the stored value must not be rewritten'
            );
            $this->assertSame('inlineStr', $cell['type']);
            $this->assertSame(
                XlsxWriterTool::STYLE_QUOTE_PREFIX,
                $cell['style'],
                "$dangerous[$i] must carry the quotePrefix style"
            );
        }
        foreach ($rows as $row) {
            foreach ($row as $cell) {
                $this->assertFalse($cell['formula'], 'no cell may hold a formula');
                $this->assertNotSame('n', $cell['type'], 'no cell may be numeric');
            }
        }
    }

    public function testLiteralPrefixIsOptIn()
    {
        $sheets = $this->export(
            [$this->attributeRow(['value' => '=SUM(1)'])],
            ['escape_formulas_literal' => 1]
        );
        $rows = $this->values(reset($sheets));
        $this->assertContains("'=SUM(1)", $rows[1]);
    }

    public function testHarmlessValuesAreNotStyled()
    {
        $sheets = $this->export([$this->attributeRow(['value' => '1.2.3.4'])]);
        $rows = reset($sheets);
        foreach ($rows[1] as $cell) {
            $this->assertSame(XlsxWriterTool::STYLE_DEFAULT, $cell['style']);
        }
    }
}
