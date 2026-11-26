<?php
/** Module-declared setting validators are limited to known ones; pure PHPUnit. */
require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package) {}
    }
}
if (!class_exists('AppModel', false)) {
    class AppModel {}
}
if (!function_exists('__')) {
    function __($text, ...$args)
    {
        return $args ? vsprintf($text, $args) : $text;
    }
}
require_once __DIR__ . '/../Model/Module.php';

class SettingTestAllowListModule extends Module
{
    public $listing = [];

    public function getModules($moduleFamily = 'Enrichment', $throwException = false)
    {
        return $this->listing;
    }
}

class ModuleSettingTestAllowListTest extends TestCase
{
    private function settingsFor(array $config)
    {
        $module = new SettingTestAllowListModule();
        $module->listing = [[
            'name' => 'mod',
            'meta' => ['module-type' => ['import'], 'config' => $config]
        ]];
        $result = $module->getModuleSettings('Import');
        $byName = [];
        foreach ($result['mod'] as $setting) {
            $byName[$setting['name']] = $setting;
        }
        return $byName;
    }

    public function testKnownValidatorIsKept()
    {
        $settings = $this->settingsFor([
            'port' => ['type' => 'numeric', 'test' => 'testForPortNumber'],
            'flag' => ['type' => 'string', 'test' => 'testForEmpty']
        ]);
        $this->assertSame('testForPortNumber', $settings['port']['test']);
        $this->assertSame('testForEmpty', $settings['flag']['test']);
    }

    public function testOtherServerMethodsAreDropped()
    {
        $settings = $this->settingsFor([
            'a' => ['type' => 'string', 'test' => 'killAllWorkers'],
            'b' => ['type' => 'string', 'test' => 'testForBinExec'],
            'c' => ['type' => 'string', 'test' => ['testBool']],
            'd' => ['type' => 'string']
        ]);
        foreach (['a', 'b', 'c', 'd'] as $name) {
            $this->assertNull($settings[$name]['test'], $name);
        }
    }
}
