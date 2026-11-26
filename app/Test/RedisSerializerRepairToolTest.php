<?php
require_once __DIR__ . '/../Lib/Tools/RedisSerializerRepairTool.php';

use PHPUnit\Framework\TestCase;

class RedisSerializerRepairToolTest extends TestCase
{
    public function testSerializedScalarsAreUnwrapped(): void
    {
        $this->assertSame('bit.ly', RedisSerializerRepairTool::unwrap('s:6:"bit.ly";'));
        $this->assertSame('', RedisSerializerRepairTool::unwrap('s:0:"";'));
        $this->assertSame('1789196730', RedisSerializerRepairTool::unwrap('i:1789196730;'));
        $this->assertSame('-3', RedisSerializerRepairTool::unwrap('i:-3;'));
        $this->assertSame('1.5', RedisSerializerRepairTool::unwrap('d:1.5;'));
        $this->assertSame('1', RedisSerializerRepairTool::unwrap('b:1;'));
        $this->assertSame('', RedisSerializerRepairTool::unwrap('b:0;'));
        $this->assertSame("a\"b;\x00", RedisSerializerRepairTool::unwrap(serialize("a\"b;\x00")));
    }

    public function testEverythingElseIsLeftAlone(): void
    {
        $untouched = [
            'bit.ly',
            '1789196730',
            '{"95":["foobar.baz","foobar.baz"]}',
            "\x00\x00\x00\x02\x14\x00",
            'N;',
            'a:1:{i:0;s:1:"x";}',
            'O:8:"stdClass":0:{}',
            's:5:"bit.ly";',
            's:6:"bit.ly";trailing',
            'i:5',
            'Auth|s:3:"abc";',
            '',
            false,
            null,
            42,
        ];
        foreach ($untouched as $value) {
            $this->assertNull(RedisSerializerRepairTool::unwrap($value), var_export($value, true));
        }
    }
}
