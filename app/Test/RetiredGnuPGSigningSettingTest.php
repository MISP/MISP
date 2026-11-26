<?php
/** A retired setting is not offered by the settings definitions or their groups; pure PHPUnit. */
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
require_once __DIR__ . '/../Model/Server.php';
require_once __DIR__ . '/../Lib/Tools/ServerSettingGroups.php';

class RetiredGnuPGSigningSettingTest extends TestCase
{
    private static function definitions()
    {
        if (!defined('ROOT')) {
            define('ROOT', dirname(__DIR__, 2));
        }
        if (!defined('APP')) {
            define('APP', ROOT . '/app/');
        }
        $server = (new ReflectionClass(new class extends Server {
            public function __construct()
            {
            }

            public function __get($name)
            {
                return '';
            }
        }))->newInstanceWithoutConstructor();
        $method = new ReflectionMethod('Server', 'generateServerSettings');
        $method->setAccessible(true);
        return $method->invoke($server);
    }

    public function testSettingDefinitionIsGone()
    {
        $settings = self::definitions();
        $this->assertArrayHasKey('key_fetching_disabled', $settings['GnuPG']);
        $this->assertArrayNotHasKey('restrict_server_signing_to_host_org', $settings['GnuPG']);
    }

    public function testSettingIsInNoGroup()
    {
        $property = new ReflectionProperty('ServerSettingGroups', 'groups');
        $property->setAccessible(true);
        $names = [];
        $groups = $property->getValue();
        array_walk_recursive($groups, function ($value) use (&$names) {
            $names[] = $value;
        });
        $this->assertContains('GnuPG.key_fetching_disabled', $names);
        $this->assertNotContains('GnuPG.restrict_server_signing_to_host_org', $names);
    }
}
