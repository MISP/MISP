<?php

use PHPUnit\Framework\TestCase;

/**
 * Feed and sync responses must be bounded after decoding, not only on the wire.
 *
 * Runs in separate processes so its stubs never leak into, or are shadowed by,
 * the stubs of other test files.
 */
class DecodedResponseLimitTest extends TestCase
{
    /** @var resource|null */
    private $server;

    /** @var string|null */
    private $dir;

    protected function tearDown(): void
    {
        if (is_resource($this->server)) {
            proc_terminate($this->server);
            proc_close($this->server);
        }
        $this->server = null;
        if ($this->dir !== null) {
            foreach (glob($this->dir . '/*') ?: [] as $file) {
                @unlink($file);
            }
            @rmdir($this->dir);
            $this->dir = null;
        }
    }

    private function load(): void
    {
        if (!class_exists('App', false)) {
            eval('class App { public static function uses($c, $p = null) {} }');
        }
        if (!class_exists('Configure', false)) {
            eval('class Configure {
                public static $values = [];
                public static function read($k) { return self::$values[$k] ?? null; }
            }');
        }
        if (!class_exists('SocketException', false)) {
            eval('class SocketException extends RuntimeException {}');
        }
        if (!class_exists('HttpSocket', false)) {
            eval('class HttpSocket { public $config = []; public function __construct($config = []) {} }');
        }
        require_once __DIR__ . '/../Lib/cakephp/lib/Cake/Network/Http/HttpSocketResponse.php';
        require_once __DIR__ . '/../Lib/Tools/DecompressLimitException.php';
        require_once __DIR__ . '/../Lib/Tools/DecompressTool.php';
        require_once __DIR__ . '/../Lib/Tools/HttpSocketExtended.php';
    }

    private static function gzipZeros(int $totalBytes): string
    {
        $ctx = deflate_init(ZLIB_ENCODING_GZIP);
        $slice = str_repeat("\0", 1048576);
        $out = '';
        for ($i = 0; $i < $totalBytes / 1048576; $i++) {
            $out .= deflate_add($ctx, $slice, ZLIB_NO_FLUSH);
        }
        return $out . deflate_add($ctx, '', ZLIB_FINISH);
    }

    private static function message(string $encoding, string $body): string
    {
        return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: $encoding\r\n"
            . 'Content-Length: ' . strlen($body) . "\r\n\r\n" . $body;
    }

    private function parse(string $message): HttpSocketResponseExtended
    {
        $response = new HttpSocketResponseExtended();
        $response->parseResponse($message);
        return $response;
    }

    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testHonestGzipBodyDecodes(): void
    {
        $this->load();
        Configure::$values['Security.max_decompressed_size'] = 100000;
        $plain = str_repeat('{"a": "b"}', 5000);
        $response = $this->parse(self::message('gzip', gzencode($plain)));
        $this->assertSame($plain, $response->body);
    }

    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGzipBombIsRefused(): void
    {
        $this->load();
        Configure::$values['Security.max_decompressed_size'] = 1048576;
        $bomb = self::gzipZeros(32 * 1048576);
        $this->assertLessThan(1048576, strlen($bomb));
        $this->expectException(SocketException::class);
        $this->expectExceptionMessage('maximum allowed size of 1048576 bytes');
        $this->parse(self::message('gzip', $bomb));
    }

    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testInvalidGzipKeepsItsMessage(): void
    {
        $this->load();
        $this->expectException(SocketException::class);
        $this->expectExceptionMessage('gzip decoding failed');
        $this->parse(self::message('gzip', str_repeat('not gzip', 50)));
    }

    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testBrotliAndZstdAreUnsupported(): void
    {
        $this->load();
        foreach (['br', 'zstd'] as $encoding) {
            try {
                $this->parse(self::message($encoding, 'abc'));
                $this->fail("$encoding was accepted");
            } catch (SocketException $e) {
                $this->assertStringContainsString('unsupported content encoding', $e->getMessage());
            }
        }
    }

    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testOnlyGzipIsAdvertised(): void
    {
        $this->load();
        $client = new HttpSocketExtended(['compress' => true]);
        $this->assertSame('gzip', $client->config['request']['header']['Accept-Encoding'] ?? null);
    }

    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testBodyCollector(): void
    {
        $this->load();
        require_once __DIR__ . '/../Lib/Tools/CurlClient.php';
        $body = '';
        $write = CurlClient::bodyCollector($body, 10);
        $this->assertSame(6, $write(null, 'abcdef'));
        $this->assertSame(4, $write(null, 'ghij'));
        $this->assertSame('abcdefghij', $body);
        $this->assertNotSame(1, $write(null, 'k'));
        $this->assertSame('abcdefghij', $body);

        $body = '';
        $write = CurlClient::bodyCollector($body, null);
        $this->assertSame(1048576, $write(null, str_repeat('x', 1048576)));
        $this->assertSame(1048576, strlen($body));
    }

    private function startServer(): string
    {
        if (!extension_loaded('curl')) {
            $this->markTestSkipped('curl extension missing');
        }
        $this->dir = sys_get_temp_dir() . '/decoded_limit_' . bin2hex(random_bytes(4));
        mkdir($this->dir, 0700);
        file_put_contents($this->dir . '/router.php', <<<'PHP'
<?php
if (isset($_GET['bomb'])) {
    $ctx = deflate_init(ZLIB_ENCODING_GZIP);
    $slice = str_repeat("\0", 1048576);
    $out = '';
    for ($i = 0; $i < 16; $i++) {
        $out .= deflate_add($ctx, $slice, ZLIB_NO_FLUSH);
    }
    header('Content-Encoding: gzip');
    echo $out . deflate_add($ctx, '', ZLIB_FINISH);
} elseif (isset($_GET['empty'])) {
    http_response_code(204);
} else {
    echo str_repeat('a', 500);
}
PHP);
        $sock = @stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        if (!$sock) {
            $this->markTestSkipped('cannot find a free port');
        }
        $port = (int)explode(':', stream_socket_get_name($sock, false))[1];
        fclose($sock);
        $cmd = [PHP_BINARY, '-S', "127.0.0.1:$port", $this->dir . '/router.php'];
        $this->server = proc_open($cmd, [['pipe', 'r'], ['file', '/dev/null', 'w'], ['file', '/dev/null', 'w']], $pipes);
        if (!is_resource($this->server)) {
            $this->markTestSkipped('cannot start php -S');
        }
        for ($i = 0; $i < 50; $i++) {
            $conn = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.2);
            if ($conn) {
                fclose($conn);
                return "http://127.0.0.1:$port";
            }
            usleep(100000);
        }
        $this->markTestSkipped('php -S did not come up');
    }

    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testCurlTransfers(): void
    {
        $this->load();
        require_once __DIR__ . '/../Lib/Tools/CurlClient.php';
        $base = $this->startServer();
        $client = new CurlClient(['timeout' => 20]);

        // under the limit, repeated on one handle
        Configure::$values['Security.max_decompressed_size'] = 1048576;
        $this->assertSame(str_repeat('a', 500), $client->get("$base/")->body);
        $this->assertSame(str_repeat('a', 500), $client->get("$base/")->body);
        $this->assertSame('', $client->head("$base/")->body);
        $this->assertSame('', $client->get("$base/?empty=1")->body);

        // a small compressed body that inflates past the limit
        try {
            $client->get("$base/?bomb=1");
            $this->fail('The decoded size was not limited');
        } catch (SocketException $e) {
            $this->assertStringContainsString('maximum allowed size of 1048576 bytes', $e->getMessage());
        }
        // the handle is still usable afterwards
        $this->assertSame(500, strlen($client->get("$base/")->body));

        // maxSize wins over the configured limit, in both directions
        $client->setMaxSize(100);
        Configure::$values['Security.max_decompressed_size'] = 1048576;
        try {
            $client->get("$base/");
            $this->fail('maxSize was not enforced');
        } catch (SocketException $e) {
            $this->assertStringContainsString('maximum allowed size of 100 bytes', $e->getMessage());
        }
        $client->setMaxSize(1000);
        Configure::$values['Security.max_decompressed_size'] = 10;
        $this->assertSame(500, strlen($client->get("$base/")->body));
    }

    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testUnzipFirstFile(): void
    {
        $this->load();
        if (!class_exists('ZipArchive')) {
            $this->markTestSkipped('zip extension missing');
        }
        if (!class_exists('AppModel', false)) {
            eval('class AppModel { public $validationErrors = []; }');
        }
        if (!class_exists('FileAccessTool', false)) {
            eval('class FileAccessTool {
                public static function createTempFile() { return tempnam(sys_get_temp_dir(), "feed"); }
                public static function readAndDelete($f) { $d = file_get_contents($f); unlink($f); return $d; }
            }');
        }
        if (!defined('DS')) {
            define('DS', DIRECTORY_SEPARATOR);
        }
        if (!defined('APP')) {
            define('APP', __DIR__ . '/../');
        }
        require_once __DIR__ . '/../Model/Feed.php';
        $feed = (new ReflectionClass('Feed'))->newInstanceWithoutConstructor();
        $unzip = new ReflectionMethod('Feed', 'unzipFirstFile');
        $unzip->setAccessible(true);

        $this->dir = sys_get_temp_dir() . '/decoded_limit_' . bin2hex(random_bytes(4));
        mkdir($this->dir, 0700);
        $small = $this->dir . '/small.zip';
        $zip = new ZipArchive();
        $zip->open($small, ZipArchive::CREATE);
        $zip->addFromString('feed.json', '{"a": 1}');
        $zip->close();
        $big = $this->dir . '/big.zip';
        file_put_contents($this->dir . '/zeros', str_repeat("\0", 16 * 1048576));
        $zip = new ZipArchive();
        $zip->open($big, ZipArchive::CREATE);
        $zip->addFile($this->dir . '/zeros', 'feed.json');
        $zip->close();

        Configure::$values['Security.max_decompressed_size'] = 1048576;
        $this->assertSame('{"a": 1}', $unzip->invoke($feed, $small));
        try {
            $unzip->invoke($feed, $big);
            $this->fail('The zip entry was not limited');
        } catch (Exception $e) {
            $this->assertStringContainsString('maximum allowed size of 1048576 bytes', $e->getMessage());
        }
        Configure::$values['Security.max_decompressed_size'] = 32 * 1048576;
        $this->assertSame(16 * 1048576, strlen($unzip->invoke($feed, $big)));
    }
}
