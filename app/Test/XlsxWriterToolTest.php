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

require_once __DIR__ . '/../Lib/Tools/TmpFileTool.php';
require_once __DIR__ . '/../Lib/Tools/XlsxWriterTool.php';

class XlsxWriterToolTest extends TestCase
{
    private function parts($binary)
    {
        $path = tempnam(sys_get_temp_dir(), 'xlsxwriter');
        file_put_contents($path, $binary);
        $zip = new ZipArchive();
        $this->assertTrue($zip->open($path) === true);
        $parts = [];
        for ($i = 0; $i < $zip->numFiles; $i++) {
            $name = $zip->getNameIndex($i);
            $parts[$name] = $zip->getFromIndex($i);
        }
        $zip->close();
        unlink($path);
        return $parts;
    }

    private function sheetRows($xml)
    {
        $sheet = simplexml_load_string($xml);
        $this->assertNotFalse($sheet, 'worksheet is not well formed XML');
        $rows = [];
        foreach ($sheet->sheetData->row as $row) {
            $cells = [];
            foreach ($row->c as $cell) {
                $cells[(string)$cell['r']] = isset($cell->is->t) ? (string)$cell->is->t : '';
            }
            $rows[] = $cells;
        }
        return $rows;
    }

    public function testEveryPartIsWellFormedXml()
    {
        $writer = new XlsxWriterTool();
        $writer->setHeader(['a', 'b']);
        $writer->addRow(['1', '2']);
        $parts = $this->parts((string)$writer->finish());

        $expected = [
            '[Content_Types].xml',
            '_rels/.rels',
            'xl/workbook.xml',
            'xl/_rels/workbook.xml.rels',
            'xl/styles.xml',
            'xl/worksheets/sheet1.xml',
        ];
        foreach ($expected as $name) {
            $this->assertArrayHasKey($name, $parts);
            $this->assertNotFalse(
                simplexml_load_string($parts[$name]),
                "$name is not well formed XML"
            );
        }
    }

    public function testStylesDeclareTheQuotePrefixFormat()
    {
        $writer = new XlsxWriterTool();
        $writer->addRow(['x']);
        $parts = $this->parts((string)$writer->finish());
        $this->assertStringContainsString('quotePrefix="1"', $parts['xl/styles.xml']);
    }

    public function testRowsRollOverIntoFurtherSheetsWithTheHeaderRepeated()
    {
        $writer = new XlsxWriterTool(['maxRowsPerSheet' => 3]);
        $writer->setHeader(['h1', 'h2']);
        for ($i = 1; $i <= 6; $i++) {
            $writer->addRow(["r$i", 'x']);
        }
        $parts = $this->parts((string)$writer->finish());
        $this->assertSame(3, $writer->sheetCount());

        $workbook = simplexml_load_string($parts['xl/workbook.xml']);
        $names = [];
        foreach ($workbook->sheets->sheet as $sheet) {
            $names[] = (string)$sheet['name'];
        }
        $this->assertSame(['MISP', 'MISP 2', 'MISP 3'], $names);

        $seen = [];
        foreach ([1, 2, 3] as $index) {
            $rows = $this->sheetRows($parts["xl/worksheets/sheet$index.xml"]);
            $this->assertCount(3, $rows, "sheet $index must hold header + 2 rows");
            $this->assertSame('h1', $rows[0]["A1"]);
            $seen[] = $rows[1]['A2'];
            $seen[] = $rows[2]['A3'];
        }
        $this->assertSame(['r1', 'r2', 'r3', 'r4', 'r5', 'r6'], $seen);
    }

    public function testOverlongValuesAreTruncatedAndCounted()
    {
        $writer = new XlsxWriterTool();
        $writer->addRow([str_repeat('x', XlsxWriterTool::MAX_CELL_LENGTH + 500), 'short']);
        $parts = $this->parts((string)$writer->finish());
        $rows = $this->sheetRows($parts['xl/worksheets/sheet1.xml']);

        $this->assertSame(1, $writer->truncatedCells());
        $this->assertSame(
            XlsxWriterTool::MAX_CELL_LENGTH,
            mb_strlen($rows[0]['A1'], 'UTF-8')
        );
        $this->assertStringEndsWith('…', $rows[0]['A1']);
        $this->assertSame('short', $rows[0]['B1']);
    }

    public function testControlCharactersAreStripped()
    {
        $writer = new XlsxWriterTool();
        $writer->addRow(["bad\x00\x01\x1Fbyte", "keep\tthe\ttabs"]);
        $parts = $this->parts((string)$writer->finish());
        $rows = $this->sheetRows($parts['xl/worksheets/sheet1.xml']);

        $this->assertSame('badbyte', $rows[0]['A1']);
        $this->assertSame("keep\tthe\ttabs", $rows[0]['B1']);
    }

    public function testInvalidUtf8IsRepaired()
    {
        $writer = new XlsxWriterTool();
        $writer->addRow(["valid \xC3\xA9", "broken \xC3\x28"]);
        $parts = $this->parts((string)$writer->finish());
        $rows = $this->sheetRows($parts['xl/worksheets/sheet1.xml']);

        $this->assertSame('valid é', $rows[0]['A1']);
        $this->assertTrue(mb_check_encoding($rows[0]['B1'], 'UTF-8'));
    }

    public function testColumnReferencesPassZ()
    {
        $writer = new XlsxWriterTool();
        $writer->addRow(array_fill(0, 28, 'v'));
        $parts = $this->parts((string)$writer->finish());
        $rows = $this->sheetRows($parts['xl/worksheets/sheet1.xml']);

        foreach (['A1', 'Z1', 'AA1', 'AB1'] as $reference) {
            $this->assertArrayHasKey($reference, $rows[0]);
        }
    }

    public function testEmptyValuesProduceEmptyCells()
    {
        $writer = new XlsxWriterTool();
        $writer->addRow(['', 'x', null]);
        $parts = $this->parts((string)$writer->finish());
        $sheet = $parts['xl/worksheets/sheet1.xml'];

        $this->assertStringContainsString('<c r="A1"/>', $sheet);
        $this->assertStringContainsString('<c r="C1"/>', $sheet);
        $this->assertNotFalse(simplexml_load_string($sheet));
    }

    public function testTooManyColumnsIsRejected()
    {
        $writer = new XlsxWriterTool();
        $this->expectException(Exception::class);
        $writer->addRow(array_fill(0, XlsxWriterTool::MAX_COLUMNS + 1, 'v'));
    }

    public function testSheetNameIsKeptWithinExcelLimits()
    {
        $writer = new XlsxWriterTool(['sheetName' => 'a/b\\c:d?e*f[g]h' . str_repeat('z', 40)]);
        $writer->addRow(['x']);
        $parts = $this->parts((string)$writer->finish());

        $workbook = simplexml_load_string($parts['xl/workbook.xml']);
        $name = (string)$workbook->sheets->sheet[0]['name'];
        $this->assertSame(31, mb_strlen($name, 'UTF-8'));
        $this->assertSame(0, preg_match('/[:\\\\\/?*\[\]]/', $name));
    }
}
