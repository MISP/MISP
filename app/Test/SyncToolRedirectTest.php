<?php

use PHPUnit\Framework\TestCase;

/**
 * Feed and sync sockets must not let libcurl follow redirects on its own.
 *
 * Runs in separate processes so its own stubs never leak into, or are
 * shadowed by, the stubs of other test files.
 */
class SyncToolRedirectTest extends TestCase
{
    private function load(): SyncTool
    {
        if (!class_exists('App', false)) {
            eval('class App { public static function uses($c, $p = null) {} }');
        }
        if (!class_exists('Configure', false)) {
            eval('class Configure {
                public static function read($k) { return null; }
                public static function check($k) { return false; }
            }');
        }
        if (!class_exists('HttpSocketExtended', false)) {
            eval('class HttpSocketExtended { public function __construct($p = []) {} public function configProxy($host, $port = 3128, $method = null, $user = null, $pass = null) {} }');
        }
        require_once __DIR__ . '/../Lib/Tools/CurlClient.php';
        require_once __DIR__ . '/../Lib/Tools/SyncTool.php';
        return new SyncTool();
    }

    private function followsRedirects(CurlClient $client): bool
    {
        $property = new ReflectionProperty(CurlClient::class, 'defaultOptions');
        $property->setAccessible(true);
        return (bool)$property->getValue($client)[CURLOPT_FOLLOWLOCATION];
    }

    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testFeedSocketDoesNotFollowRedirects(): void
    {
        $client = $this->load()->setupHttpSocketFeed();
        $this->assertInstanceOf(CurlClient::class, $client);
        $this->assertFalse($this->followsRedirects($client));
    }

    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testSyncSocketDoesNotFollowRedirects(): void
    {
        $tool = $this->load();
        $client = $tool->setupHttpSocket(['Server' => ['url' => 'https://example.com']], 5);
        $this->assertInstanceOf(CurlClient::class, $client);
        $this->assertFalse($this->followsRedirects($client));
        $client = $tool->setupHttpSocket();
        $this->assertFalse($this->followsRedirects($client));
    }

    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testPlainSocketStillFollowsRedirects(): void
    {
        $client = $this->load()->createHttpSocket();
        $this->assertTrue($this->followsRedirects($client));
    }
}
