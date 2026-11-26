<?php
require_once __DIR__ . '/../Lib/Export/CsvExport.php';

use PHPUnit\Framework\TestCase;

class CsvExportQuotingTest extends TestCase
{
    private function escape($field)
    {
        $export = new CsvExport();
        $method = new ReflectionMethod($export, '__escapeCSVField');
        $method->setAccessible(true);
        return $method->invoke($export, $field);
    }

    public function testPlainNumbersStayUnquoted()
    {
        foreach (['0', '42', '-7', '3.14', '-0.5'] as $number) {
            $this->assertSame($number, $this->escape($number));
        }
        $this->assertEquals('5', $this->escape(5));
    }

    public function testNumericLookingFieldsWithWhitespaceAreQuoted()
    {
        foreach ([" 1", "1 ", "1\n", "1\r\n", "\n1", "1\n2,x", "\t1", "1e3", "+1", ".5", "0x1A"] as $field) {
            $escaped = $this->escape($field);
            $this->assertSame('"' . $field . '"', $escaped, var_export($field, true));
        }
    }

    public function testQuotesAreDoubled()
    {
        $this->assertSame('"a""b"', $this->escape('a"b'));
    }

    public function testBooleans()
    {
        $this->assertSame('1', $this->escape(true));
        $this->assertSame('0', $this->escape(false));
    }
}
