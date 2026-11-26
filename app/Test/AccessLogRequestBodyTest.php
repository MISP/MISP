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

require_once __DIR__ . '/../Lib/Tools/DecompressLimitException.php';
require_once __DIR__ . '/../Lib/Tools/DecompressTool.php';

class AccessLogRequestBodyModelStub
{
}

class AccessLogRequestBodyRequestStub
{
    public $data = [];

    public function input($callback = null)
    {
        return '';
    }
}

class AccessLogRequestBodyTest extends TestCase
{
    private $server;

    protected function setUp(): void
    {
        $this->server = $_SERVER;
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->server;
    }

    private static function model()
    {
        if (!class_exists('AppModel', false)) {
            class_alias('AccessLogRequestBodyModelStub', 'AppModel');
        }
        if (!class_exists('CakeRequest', false)) {
            class_alias('AccessLogRequestBodyRequestStub', 'CakeRequest');
        }
        require_once __DIR__ . '/../Model/AccessLog.php';
        return (new ReflectionClass('AccessLog'))->newInstanceWithoutConstructor();
    }

    private static function call($model, $method, array $args)
    {
        $m = new ReflectionMethod($model, $method);
        $m->setAccessible(true);
        return $m->invokeArgs($model, $args);
    }

    private static function request($body)
    {
        self::model();
        $class = new class extends CakeRequest {
            public $body = '';

            public function __construct()
            {
            }

            public function input($callback = null)
            {
                return $this->body;
            }
        };
        $class->body = $body;
        return $class;
    }

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

    public function testGzipRequestIsStoredWithEmptyEncoding(): void
    {
        $_SERVER['CONTENT_TYPE'] = 'application/json';
        $_SERVER['HTTP_CONTENT_ENCODING'] = 'gzip';
        $model = self::model();
        $stored = self::call($model, 'requestBody', [self::request('{"a":1}')]);
        $this->assertSame("application/json\n\n{\"a\":1}", $stored);
        $this->assertSame(
            ['application/json', '', '{"a":1}'],
            self::call($model, 'decodeRequest', [$stored])
        );
    }

    public function testOldRowLabelledGzipWithPlainBody(): void
    {
        $row = "application/json\ngzip\n{\"a\":1}";
        $this->assertSame(
            ['application/json', 'gzip', '{"a":1}'],
            self::call(self::model(), 'decodeRequest', [$row])
        );
    }

    public function testOldRowLabelledGzipWithGzipBody(): void
    {
        $row = "application/json\ngzip\n" . gzencode('{"a":1}');
        $this->assertSame('{"a":1}', self::call(self::model(), 'decodeRequest', [$row])[2]);
    }

    public function testOldRowWithBodyBeyondDisplayLimitDoesNotInflate(): void
    {
        $row = "application/json\ngzip\n" . self::gzipZeros(64 * 1048576);
        $data = self::call(self::model(), 'decodeRequest', [$row])[2];
        $this->assertLessThan(1048576, strlen($data));
    }

    public function testOldBrRowIsReturnedAsStored(): void
    {
        $body = function_exists('brotli_compress') ? brotli_compress('{"a":1}') : "\x0b\x03\x80{\"a\":1}";
        $row = "application/json\nbr\n" . $body;
        $this->assertSame($body, self::call(self::model(), 'decodeRequest', [$row])[2]);
    }
}
