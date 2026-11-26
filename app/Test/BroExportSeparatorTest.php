<?php

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Vendor/autoload.php';
require_once __DIR__ . '/../Lib/Export/BroExport.php';

class BroExportSeparatorTest extends TestCase
{
    public function testEntitiesCannotProduceSeparators()
    {
        $out = BroExport::replaceIllegalChars("a&#9;b&#10;c&#13;d\x0Be\tf\ng");
        $this->assertStringNotContainsString("\t", $out);
        $this->assertStringNotContainsString("\n", $out);
        $this->assertStringNotContainsString("\r", $out);
        $this->assertStringNotContainsString("\x0B", $out);
        $this->assertSame('a b c d e f g', $out);
    }

    public function testOrdinaryTextIsUnchanged()
    {
        $this->assertSame('Some comment, with "quotes" & more', BroExport::replaceIllegalChars('Some comment, with "quotes" & more'));
    }

    public function testOrganisationNameCannotBreakTheLine()
    {
        if (!class_exists('Configure')) {
            eval('class Configure { public static function read($k = null) { return "http://misp.example"; } }');
        }
        $export = new BroExport();
        $item = [
            'Event' => ['id' => 1, 'uuid' => 'u', 'orgc_id' => 2, 'info' => 'i'],
            'Attribute' => ['type' => 'domain', 'value1' => 'evil.example', 'comment' => 'c'],
        ];
        $lines = $export->export([$item], [2 => "Org\t%s\n%d&#9;x"], 1, 'MISP');
        $this->assertCount(1, $lines);
        $this->assertStringNotContainsString("\n", $lines[0]);
        $this->assertSame(7, count(explode("\t", $lines[0])));
        $this->assertStringContainsString('Org %s %d x', $lines[0]);
    }
}
