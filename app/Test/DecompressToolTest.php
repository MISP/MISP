<?php

use PHPUnit\Framework\TestCase;

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package = null)
        {
        }
    }
}

require_once __DIR__ . '/../Lib/Tools/DecompressLimitException.php';
require_once __DIR__ . '/../Lib/Tools/DecompressTool.php';

class DecompressToolTest extends TestCase
{
    private static function gzipZeros($totalBytes)
    {
        $ctx = deflate_init(ZLIB_ENCODING_GZIP);
        $slice = str_repeat("\0", 1048576);
        $out = '';
        for ($i = 0; $i < $totalBytes / 1048576; $i++) {
            $out .= deflate_add($ctx, $slice, ZLIB_NO_FLUSH);
        }
        return $out . deflate_add($ctx, '', ZLIB_FINISH);
    }

    public function testGzipRoundTrip(): void
    {
        $plain = str_repeat('{"a": "b"}', 5000);
        $this->assertSame($plain, DecompressTool::decode('gzip', gzencode($plain)));
        $this->assertSame($plain, DecompressTool::decode('gzip', gzencode($plain), strlen($plain)));
        $this->assertSame($plain, DecompressTool::decode('gzip', gzencode($plain), 0));
    }

    public function testGzipOverTheLimit(): void
    {
        $plain = str_repeat('x', 100000);
        $this->expectException(DecompressLimitException::class);
        DecompressTool::decode('gzip', gzencode($plain), 50000);
    }

    public function testGzipBombStopsEarly(): void
    {
        $bomb = self::gzipZeros(64 * 1048576);
        $this->assertLessThan(1048576, strlen($bomb));
        if (function_exists('memory_reset_peak_usage')) {
            memory_reset_peak_usage();
        }
        $before = memory_get_usage();
        try {
            DecompressTool::decode('gzip', $bomb, 1048576);
            $this->fail('The limit was not enforced');
        } catch (DecompressLimitException $e) {
            $this->addToAssertionCount(1);
        }
        if (function_exists('memory_reset_peak_usage')) {
            $this->assertLessThan(24 * 1048576, memory_get_peak_usage() - $before);
        }
    }

    public function testTruncatedGzipIsInvalid(): void
    {
        $data = gzencode(str_repeat('abc', 10000));
        $this->expectException(InvalidArgumentException::class);
        DecompressTool::decode('gzip', substr($data, 0, -12));
    }

    public function testCorruptGzipIsInvalid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        DecompressTool::decode('gzip', str_repeat('not gzip data', 100));
    }

    public function testUnsupportedEncodingRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        DecompressTool::decode('deflate', 'abc');
    }

    public function testOnlyGzipIsSupported(): void
    {
        $this->assertSame(['gzip'], DecompressTool::supportedEncodings());
        foreach (['br', 'zstd'] as $encoding) {
            try {
                DecompressTool::decode($encoding, 'abc');
                $this->fail("$encoding was accepted");
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString('Unsupported', $e->getMessage());
            }
        }
    }
}
