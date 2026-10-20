<?php
/**
 * PluginMapGuard drops Cake's cached plugin list when it names a plugin that
 * was removed from the tree. Pure PHPUnit, no CakePHP bootstrap, no DB.
 */

require_once __DIR__ . '/../Vendor/autoload.php';
require_once __DIR__ . '/../Lib/Tools/PluginMapGuard.php';

use PHPUnit\Framework\TestCase;

class PluginMapGuardTest extends TestCase
{
    private $app;

    protected function setUp(): void
    {
        $this->app = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'plugin_map_guard_' . bin2hex(random_bytes(4));
        mkdir($this->app . '/Plugin', 0777, true);
        mkdir($this->app . '/tmp/cache/persistent', 0777, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->app . '/{tmp/cache/persistent/*,Plugin/*,}', GLOB_BRACE) as $path) {
            is_dir($path) ? @rmdir($path) : @unlink($path);
        }
        @rmdir($this->app . '/tmp/cache/persistent');
        @rmdir($this->app . '/tmp/cache');
        @rmdir($this->app . '/tmp');
        @rmdir($this->app . '/Plugin');
        @rmdir($this->app);
    }

    private function cache(array $plugins)
    {
        $file = $this->app . '/tmp/cache/persistent/myapp_cake_core_object_map';
        file_put_contents($file, "1878790317\n" . serialize(array(false, 'app' => array('plugins' => $plugins))));
        return $file;
    }

    public function testAListedPluginThatIsGoneRemovesTheCache()
    {
        mkdir($this->app . '/Plugin/SysLog');
        $file = $this->cache(array('SysLog', 'UrlCache'));
        $result = PluginMapGuard::heal($this->app);
        $this->assertSame(array('file' => $file, 'removed' => true), $result);
        $this->assertFileNotExists($file);
    }

    public function testAnIntactListIsLeftAlone()
    {
        mkdir($this->app . '/Plugin/SysLog');
        mkdir($this->app . '/Plugin/DebugKit');
        $file = $this->cache(array('DebugKit', 'SysLog'));
        $this->assertNull(PluginMapGuard::heal($this->app));
        $this->assertFileExists($file);
    }

    public function testAnUnderscoredDirectoryCountsAsThePlugin()
    {
        mkdir($this->app . '/Plugin/magic_tools');
        $file = $this->cache(array('MagicTools'));
        $this->assertNull(PluginMapGuard::heal($this->app));
        $this->assertFileExists($file);
    }

    public function testAPluginInAnotherSearchPathCounts()
    {
        $extra = $this->app . '/more/';
        mkdir($extra . 'Elsewhere', 0777, true);
        $file = $this->cache(array('Elsewhere'));
        $this->assertNull(PluginMapGuard::heal($this->app, array($extra)));
        $this->assertFileExists($file);
        rmdir($extra . 'Elsewhere');
        rmdir($extra);
    }

    public function testNoCacheFileOrAnUnreadableOneChangesNothing()
    {
        $this->assertNull(PluginMapGuard::heal($this->app));
        $file = $this->app . '/tmp/cache/persistent/myapp_cake_core_object_map';
        foreach (array('', "123\n", "123\nnot serialized", "123\n" . serialize('a string'), "123\n" . serialize(array('app' => array()))) as $content) {
            file_put_contents($file, $content);
            $this->assertNull(PluginMapGuard::heal($this->app), var_export($content, true));
            $this->assertFileExists($file);
        }
    }

    public function testAnObjectInTheCacheIsNotInstantiated()
    {
        $file = $this->app . '/tmp/cache/persistent/myapp_cake_core_object_map';
        file_put_contents($file, "123\n" . 'O:8:"stdClass":0:{}');
        $this->assertNull(PluginMapGuard::heal($this->app));
        $this->assertFileExists($file);
    }

    public function testAFileThatCannotBeDeletedIsReportedNotThrown()
    {
        $file = $this->cache(array('UrlCache'));
        chmod($this->app . '/tmp/cache/persistent', 0555);
        $result = PluginMapGuard::heal($this->app);
        chmod($this->app . '/tmp/cache/persistent', 0777);
        if (is_writable($this->app . '/tmp/cache/persistent') && function_exists('posix_geteuid') && posix_geteuid() === 0) {
            $this->markTestSkipped('root can delete anything');
        }
        $this->assertSame(array('file' => $file, 'removed' => false), $result);
    }
}
