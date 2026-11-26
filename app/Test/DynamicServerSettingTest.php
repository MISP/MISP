<?php
/**
 * Per-module settings only exist in Server::getCurrentServerSettings(), so
 * every module family it generates them for must be routed there on edit.
 * Pure PHPUnit, no CakePHP bootstrap.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

use PHPUnit\Framework\TestCase;

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }
    }
}
if (!class_exists('AppModel', false)) {
    class AppModel
    {
    }
}
if (!function_exists('__')) {
    function __($text, ...$args)
    {
        return $args ? vsprintf($text, $args) : $text;
    }
}

require_once __DIR__ . '/../Model/Server.php';

class DynamicServerSettingTest extends TestCase
{
    public function testGatheringModuleSettingsAreDynamic()
    {
        foreach (['enabled', 'restrict', 'execution_timeout', 'api_key'] as $p) {
            $name = 'Plugin.Gathering_beaconbeagle_gathering_' . $p;
            $this->assertTrue(Server::isDynamicSetting($name), $name);
        }
    }

    public function testEveryModuleFamilyIsDynamic()
    {
        foreach (Server::MODULE_SETTING_FAMILIES as $family) {
            $name = 'Plugin.' . $family . '_somemodule_enabled';
            $this->assertTrue(Server::isDynamicSetting($name), $name);
        }
    }

    public function testWorkflowTriggerIsDynamic()
    {
        $this->assertTrue(
            Server::isDynamicSetting('Plugin.Workflow_triggers_event-publish')
        );
    }

    public function testStaticSettingsAreNot()
    {
        $static = [
            'MISP.baseurl',
            'Plugin.ZeroMQ_enable',
            'Plugin.AI_services_enable',
            'Security.Plugin.Gathering_x',
        ];
        foreach ($static as $name) {
            $this->assertFalse(Server::isDynamicSetting($name), $name);
        }
    }
}
