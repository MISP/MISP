<?php
/** Per-module query budgets; pure PHPUnit, no CakePHP bootstrap, DB or network. */
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

class TimeoutTestModule extends Module
{
    public $settings = [];
    public $listings = [];
    public $requests = [];

    protected function moduleTimeoutSetting($name)
    {
        return $this->settings[$name] ?? null;
    }

    public function sendRequest($uri, $timeout, $postData = null, $moduleFamily = 'Enrichment')
    {
        $this->requests[] = compact('uri', 'timeout', 'postData', 'moduleFamily');
        if ($uri === '/modules') {
            $listing = $this->listings[$moduleFamily] ?? [];
            if ($listing instanceof Exception) {
                throw $listing;
            }
            return $listing;
        }
        return ['results' => []];
    }
}

class ModuleTimeoutTest extends TestCase
{
    private function listing($name = 'slow', array $meta = [], $type = 'import')
    {
        return ['name' => $name, 'meta' => $meta + ['module-type' => [$type]]];
    }

    private function query(TimeoutTestModule $module, $family = 'Import', $hover = false, array $payload = [])
    {
        $payload += ['module' => 'slow', 'data' => 'input', 'config' => ['timeout' => 7]];
        $result = $module->queryModuleServer($payload, $hover, $family, false, [], true);
        $this->assertSame(['results' => []], $result);
        $request = end($module->requests);
        $this->assertSame('/query', $request['uri']);
        $this->assertSame($family, $request['moduleFamily']);
        $this->assertSame($request['timeout'], $request['postData']['timeout']);
        $this->assertSame(7, $request['postData']['config']['timeout']);
        $this->assertSame('input', $request['postData']['data']);
        return $request['timeout'];
    }

    public function testConfiguredModuleTimeoutOverridesTheFamilyForBothBudgets()
    {
        $module = new TimeoutTestModule();
        $module->settings = ['Plugin.Import_timeout' => 10, 'Plugin.Import_slow_execution_timeout' => '120'];
        $this->assertSame(120, $this->query($module));
        $this->assertCount(1, $module->requests); // No discovery needed for an explicit setting.
        $this->assertSame(10, $this->query($module, 'Import', false, ['module' => 'other']));
    }

    public function testExplicitRequestWinsAndUsesTheSameHttpTimeout()
    {
        $module = new TimeoutTestModule();
        $module->settings = ['Plugin.Import_slow_execution_timeout' => 120];
        $this->assertSame(240, $this->query($module, 'Import', false, ['timeout' => '240']));
        $this->assertCount(1, $module->requests);
    }

    public function testMetadataDefaultAndAdminOverride()
    {
        $module = new TimeoutTestModule();
        $module->listings['Import'] = [$this->listing('slow', ['timeout' => 180])];
        $module->settings['Plugin.Import_timeout'] = 10;
        $this->assertSame(180, $this->query($module));
        $module->settings['Plugin.Import_slow_execution_timeout'] = 30;
        $this->assertSame(30, $this->query($module));
        $module->settings['Plugin.Import_slow_execution_timeout'] = 0;
        $this->assertSame(180, $this->query($module));
    }

    public function testDiscoveryIsReusedWithinTheModelAndRefreshedByGetModules()
    {
        $module = new TimeoutTestModule();
        $module->listings['Import'] = [$this->listing('slow', ['timeout' => 180])];
        $module->getModules('Import');
        $this->query($module);
        $this->query($module);
        $this->assertCount(3, $module->requests);
        $module->listings['Import'] = [$this->listing('slow', ['timeout' => 60])];
        $module->getModules('Import');
        $this->assertSame(60, $this->query($module));
    }

    public function testDefaultsAreIsolatedByFamilyAndModuleName()
    {
        $module = new TimeoutTestModule();
        $module->listings['Import'] = [$this->listing('slow', ['timeout' => 180])];
        $module->listings['Export'] = [$this->listing('slow', ['timeout' => 90], 'export')];
        $this->assertSame(180, $this->query($module));
        $this->assertSame(90, $this->query($module, 'Export'));
        $this->assertSame(10, $this->query($module, 'Import', false, ['module' => 'other']));
    }

    public function testHoverKeepsItsOwnBudget()
    {
        $module = new TimeoutTestModule();
        $module->settings = ['Plugin.Enrichment_timeout' => 40, 'Plugin.Enrichment_hover_timeout' => 3,
            'Plugin.Enrichment_slow_execution_timeout' => 120];
        $module->listings['Enrichment'] = [$this->listing('slow', ['timeout' => 180], 'hover')];
        $this->assertSame(3, $this->query($module, 'Enrichment', true));
        $module->listings['Enrichment'][0]['meta']['hover_timeout'] = 8;
        $module->getModules('Enrichment');
        $this->assertSame(8, $this->query($module, 'Enrichment', true));
        $module->settings['Plugin.Enrichment_slow_hover_execution_timeout'] = 15;
        $this->assertSame(15, $this->query($module, 'Enrichment', true));
        $this->assertSame(2, $this->query($module, 'Enrichment', true, ['timeout' => 2]));
    }

    public function testLegacyFallbacksAndNullRequestTimeout()
    {
        $module = new TimeoutTestModule();
        $this->assertSame(10, $this->query($module, 'Import', false, ['timeout' => null]));
        $this->assertSame(5, $this->query($module, 'Enrichment', true));
        $module->settings['Plugin.Import_timeout'] = '25';
        $this->assertSame(25, $this->query($module));
    }

    /** @dataProvider invalidTimeouts */
    public function testInvalidDefaultsFallBack($invalid)
    {
        $module = new TimeoutTestModule();
        $module->listings['Import'] = [$this->listing('slow', ['timeout' => $invalid])];
        $module->settings = ['Plugin.Import_slow_execution_timeout' => $invalid, 'Plugin.Import_timeout' => 22];
        $this->assertSame(22, $this->query($module));
    }

    /** @dataProvider invalidTimeouts */
    public function testInvalidExplicitTimeoutIsRejectedBeforeAnyHttpRequest($invalid)
    {
        if ($invalid === null) {
            $this->assertSame(10, $this->query(new TimeoutTestModule(), 'Import', false, ['timeout' => null]));
            return;
        }
        $module = new TimeoutTestModule();
        try {
            $this->query($module, 'Import', false, ['timeout' => $invalid]);
            $this->fail('Expected an invalid timeout to be rejected.');
        } catch (InvalidArgumentException $e) {
            $this->assertSame('Module timeout must be a positive integer in seconds.', $e->getMessage());
            $this->assertSame([], $module->requests);
        }
    }

    public function invalidTimeouts()
    {
        return [[null], [''], [0], ['0'], [-1], [1.5], ['1.5'], [true], [false], ['invalid'], [[]], [new stdClass()], ['999999999999999999999999999']];
    }

    public function testUnavailableDiscoveryStillQueriesWithTheFamilyBudget()
    {
        $module = new TimeoutTestModule();
        $module->listings['Import'] = new RuntimeException('unavailable');
        $module->settings['Plugin.Import_timeout'] = 20;
        $this->assertSame(20, $this->query($module));
        $this->assertSame(20, $this->query($module));
        $this->assertCount(3, $module->requests);
    }

    public function testSettingsExposeDefaultsAndKeepApiTimeoutDistinct()
    {
        $module = new TimeoutTestModule();
        $module->listings['Enrichment'] = [$this->listing('slow', [
            'module-type' => ['expansion', 'hover'], 'timeout' => 120, 'hover_timeout' => 8,
            'config' => ['timeout', 'execution_timeout', 'hover_execution_timeout', 'apikey']
        ])];
        $settings = array_column($module->getModuleSettings('Enrichment')['slow'], null, 'name');
        $this->assertSame(120, $settings['execution_timeout']['value']);
        $this->assertSame('numeric', $settings['execution_timeout']['type']);
        $this->assertSame('testForPositiveInteger', $settings['execution_timeout']['test']);
        $this->assertSame(8, $settings['hover_execution_timeout']['value']);
        $this->assertSame('string', $settings['timeout']['type']);
        $this->assertArrayHasKey('apikey', $settings);
    }

    public function testSettingsAreAvailableAcrossModuleFamilies()
    {
        foreach (['Import' => 'import', 'Export' => 'export', 'Enrichment' => 'expansion', 'Action' => 'action', 'Cortex' => 'cortex'] as $family => $type) {
            $module = new TimeoutTestModule();
            $module->listings[$family] = [$this->listing('slow', [], $type)];
            $settings = array_column($module->getModuleSettings($family)['slow'], null, 'name');
            $this->assertSame(0, $settings['execution_timeout']['value']);
            $this->assertArrayNotHasKey('hover_execution_timeout', $settings);
            $module->settings['Plugin.' . $family . '_slow_execution_timeout'] = 120;
            $this->assertSame(120, $this->query($module, $family));
        }
    }
}
