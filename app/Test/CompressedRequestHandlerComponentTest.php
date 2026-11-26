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

if (!class_exists('Component', false)) {
    class Component
    {
    }
}

if (!class_exists('BadRequestException', false)) {
    class BadRequestException extends RuntimeException
    {
    }
}

if (!class_exists('HttpException', false)) {
    class HttpException extends RuntimeException
    {
    }
}

if (!class_exists('Configure', false)) {
    class Configure
    {
        private static $values = array();
        public static function read($key) { return isset(self::$values[$key]) ? self::$values[$key] : null; }
        public static function check($key) { return isset(self::$values[$key]); }
        public static function write($key, $value) { self::$values[$key] = $value; }
        public static function reset() { self::$values = array(); }
    }
}

if (!class_exists('Controller', false)) {
    class Controller
    {
        public $here = '/feeds/enable/2';
        public $request;
    }
}

if (!class_exists('CakeErrorController', false)) {
    class CakeErrorController extends Controller
    {
    }
}

if (!class_exists('DecompressStubRequest', false)) {
    class DecompressStubRequest
    {
        public $body;
        public $inputCalls = 0;
        public $failOnInput = false;

        public function __construct($body = '')
        {
            $this->body = $body;
        }

        public function input()
        {
            $this->inputCalls++;
            if ($this->failOnInput) {
                throw new LogicException('The request body must not be read');
            }
            return $this->body;
        }

        public function setInput($input)
        {
            $this->body = $input;
        }
    }
}

require_once __DIR__ . '/../Lib/Tools/DecompressLimitException.php';
require_once __DIR__ . '/../Lib/Tools/DecompressTool.php';
require_once __DIR__ . '/../Controller/Component/CompressedRequestHandlerComponent.php';

class CompressedRequestHandlerComponentTest extends TestCase
{
    private $memoryLimit;

    protected function setUp(): void
    {
        $this->memoryLimit = ini_get('memory_limit');
        unset($_SERVER['HTTP_CONTENT_ENCODING']);
        Configure::reset();
    }

    protected function tearDown(): void
    {
        ini_set('memory_limit', $this->memoryLimit);
        unset($_SERVER['HTTP_CONTENT_ENCODING']);
        Configure::reset();
    }

    private function controller($body, $class = 'Controller')
    {
        $controller = new $class();
        $controller->request = new DecompressStubRequest($body);
        return $controller;
    }

    public function testInitializeDoesNotTouchEncodedInput(): void
    {
        $_SERVER['HTTP_CONTENT_ENCODING'] = 'gzip';
        $controller = $this->controller(gzencode('{"a": 1}'));
        $original = $controller->request->body;
        try {
            (new CompressedRequestHandlerComponent())->initialize($controller);
        } catch (Throwable $e) {
            $this->fail('initialize() must not decode the request: ' . $e->getMessage());
        }
        $this->assertSame($original, $controller->request->body);
        $this->assertSame(0, $controller->request->inputCalls);
    }

    public function testRejectEncodedRequestNeverReadsBody(): void
    {
        $_SERVER['HTTP_CONTENT_ENCODING'] = 'gzip';
        $controller = $this->controller('whatever');
        $controller->request->failOnInput = true;
        try {
            (new CompressedRequestHandlerComponent())->rejectEncodedRequest($controller);
            $this->fail('No exception thrown');
        } catch (BadRequestException $e) {
            $this->assertSame('Compressed requests are accepted only from authenticated users.', $e->getMessage());
        }
        $this->assertSame(0, $controller->request->inputCalls);
    }

    public function testRejectEncodedRequestAllowsPlainRequest(): void
    {
        $controller = $this->controller('plain');
        (new CompressedRequestHandlerComponent())->rejectEncodedRequest($controller);
        $this->assertSame(0, $controller->request->inputCalls);
    }

    public function testErrorControllerIsLeftAlone(): void
    {
        $_SERVER['HTTP_CONTENT_ENCODING'] = 'gzip';
        $controller = $this->controller('x', 'CakeErrorController');
        $component = new CompressedRequestHandlerComponent();
        $component->rejectEncodedRequest($controller);
        $component->decodeRequest($controller);
        $this->assertSame(0, $controller->request->inputCalls);
    }

    public function testDecodeRequestDecodesGzip(): void
    {
        $_SERVER['HTTP_CONTENT_ENCODING'] = 'gzip';
        $controller = $this->controller(gzencode('{"limit": 1}'));
        (new CompressedRequestHandlerComponent())->decodeRequest($controller);
        $this->assertSame('{"limit": 1}', $controller->request->body);
    }

    public function testDecodeRequestWithoutEncodingIsNoop(): void
    {
        $controller = $this->controller('{"limit": 1}');
        (new CompressedRequestHandlerComponent())->decodeRequest($controller);
        $this->assertSame(0, $controller->request->inputCalls);
    }

    public function testDecodeRequestOverTheCapIs413(): void
    {
        $_SERVER['HTTP_CONTENT_ENCODING'] = 'gzip';
        Configure::write('Security.max_decompressed_size', 1000);
        $controller = $this->controller(gzencode(str_repeat('a', 100000)));
        try {
            (new CompressedRequestHandlerComponent())->decodeRequest($controller);
            $this->fail('No exception thrown');
        } catch (HttpException $e) {
            $this->assertSame(413, $e->getCode());
        }
    }

    public function testDecodeRequestErrors(): void
    {
        $component = new CompressedRequestHandlerComponent();
        $_SERVER['HTTP_CONTENT_ENCODING'] = 'deflate';
        try {
            $component->decodeRequest($this->controller('x'));
            $this->fail('No exception thrown');
        } catch (BadRequestException $e) {
            $this->assertSame("Unsupported content encoding 'deflate'.", $e->getMessage());
        }
        $_SERVER['HTTP_CONTENT_ENCODING'] = 'br';
        $request = $this->controller('x');
        $request->request->failOnInput = true;
        try {
            $component->decodeRequest($request);
            $this->fail('No exception thrown');
        } catch (BadRequestException $e) {
            $this->assertSame("This server doesn't support brotli compressed requests.", $e->getMessage());
        }
        $_SERVER['HTTP_CONTENT_ENCODING'] = 'gzip';
        try {
            $component->decodeRequest($this->controller(''));
            $this->fail('No exception thrown');
        } catch (BadRequestException $e) {
            $this->assertStringContainsString('empty', $e->getMessage());
        }
        try {
            $component->decodeRequest($this->controller('not gzip'));
            $this->fail('No exception thrown');
        } catch (BadRequestException $e) {
            $this->assertSame('Invalid compressed data.', $e->getMessage());
        }
    }

    public function testLimitResolution(): void
    {
        $component = new CompressedRequestHandlerComponent();
        ini_set('memory_limit', '1G');
        $this->assertSame(1073741824, $component->maxDecompressedSize());
        Configure::write('Security.max_decompressed_size', 0);
        $this->assertSame(1073741824, $component->maxDecompressedSize());
        Configure::write('Security.max_decompressed_size', '5000');
        $this->assertSame(5000, $component->maxDecompressedSize());
        Configure::write('Security.max_decompressed_size', null);
        ini_set('memory_limit', '-1');
        $this->assertNull($component->maxDecompressedSize());
        Configure::write('Security.max_decompressed_size', 5000);
        $this->assertSame(5000, $component->maxDecompressedSize());
    }

    public function testIniToBytes(): void
    {
        $this->assertNull(DecompressTool::iniToBytes('-1'));
        $this->assertSame(134217728, DecompressTool::iniToBytes('134217728'));
        $this->assertSame(524288, DecompressTool::iniToBytes('512K'));
        $this->assertSame(524288, DecompressTool::iniToBytes('512k'));
        $this->assertSame(134217728, DecompressTool::iniToBytes('128M'));
        $this->assertSame(2147483648, DecompressTool::iniToBytes('2G'));
        $this->assertSame(2147483648, DecompressTool::iniToBytes('2g'));
    }
}
