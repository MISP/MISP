<?php
/**
 * The `float` server-setting type: the shared cast helper every save path
 * (web, REST, CLI) goes through, and the range validators the Plugin.AI_*
 * settings use as their `test`.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB (the app/Test convention).
 * Server.php only needs App::uses() and AppModel to exist at load time; __()
 * is stubbed so validator messages come back as plain strings. The validators
 * are instance methods, so Server is instantiated without its constructor.
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

class ServerSettingFloatTypeTest extends TestCase
{
    private static function server()
    {
        return (new ReflectionClass('Server'))->newInstanceWithoutConstructor();
    }

    // ---- normaliseSettingValue -------------------------------------------

    public function testFloatSettingIsCastToFloat()
    {
        $value = Server::normaliseSettingValue(['type' => 'float'], '0.7');
        $this->assertSame(0.7, $value);
        $this->assertSame(0.0, Server::normaliseSettingValue(['type' => 'float'], '0'));
        $this->assertSame(2.0, Server::normaliseSettingValue(['type' => 'float'], 2));
        $this->assertSame(1000.0, Server::normaliseSettingValue(['type' => 'float'], '1e3'));
    }

    public function testNonNumericFloatInputIsLeftForTheValidator()
    {
        // Not silently 0.0: the setting's test must get the chance to reject it.
        $this->assertSame('abc', Server::normaliseSettingValue(['type' => 'float'], 'abc'));
        $this->assertSame('', Server::normaliseSettingValue(['type' => 'float'], ''));
    }

    public function testNumericStillTruncatesToInt()
    {
        // The pre-existing behaviour the float type exists to avoid.
        $this->assertSame(0, Server::normaliseSettingValue(['type' => 'numeric'], '0.7'));
        $this->assertSame(7, Server::normaliseSettingValue(['type' => 'numeric'], '7'));
    }

    public function testOtherTypesUnchanged()
    {
        $this->assertTrue(Server::normaliseSettingValue(['type' => 'boolean'], '1'));
        $this->assertFalse(Server::normaliseSettingValue(['type' => 'boolean'], ''));
        $this->assertSame('0.7', Server::normaliseSettingValue(['type' => 'string'], '0.7'));
        $this->assertSame('0.7', Server::normaliseSettingValue([], '0.7'));
    }

    // ---- floatInRange ----------------------------------------------------

    public function testFloatInRangeBothBounds()
    {
        $test = self::server()->floatInRange(0, 1);
        $this->assertTrue($test('0.5'));
        $this->assertTrue($test(0));
        $this->assertTrue($test('1'));
        $this->assertTrue($test(1.0));
        $this->assertSame('The value has to be a number between 0 and 1.', $test('1.5'));
        $this->assertSame('The value has to be a number between 0 and 1.', $test(-0.1));
        $this->assertSame('This setting has to be a number.', $test('abc'));
        $this->assertSame('This setting has to be a number.', $test(''));
    }

    public function testFloatInRangeOpenBounds()
    {
        $min = self::server()->floatInRange(0, null);
        $this->assertTrue($min(99.5));
        $this->assertTrue($min('0'));
        $this->assertSame('The value has to be a number greater or equal 0.', $min(-1));

        $max = self::server()->floatInRange(null, 2);
        $this->assertTrue($max(-50));
        $this->assertSame('The value has to be a number lower or equal 2.', $max('2.01'));

        $any = self::server()->floatInRange();
        $this->assertTrue($any(-1e9));
        $this->assertSame('This setting has to be a number.', $any('x'));
    }

    // ---- integerInRange --------------------------------------------------

    public function testIntegerInRangeBothBounds()
    {
        $test = self::server()->integerInRange(1, 10);
        $this->assertTrue($test(7));
        $this->assertTrue($test('10'));
        $this->assertTrue($test(1));
        $this->assertTrue($test('7.0'));
        $this->assertSame('The value has to be a whole number between 1 and 10.', $test(0));
        $this->assertSame('The value has to be a whole number between 1 and 10.', $test(11));
        $this->assertSame('The value has to be a whole number.', $test('7.5'));
        $this->assertSame('The value has to be a whole number.', $test('abc'));
    }

    public function testIntegerInRangeOpenBounds()
    {
        $min = self::server()->integerInRange(1, null);
        $this->assertTrue($min(1000));
        $this->assertSame('The value has to be a whole number greater or equal 1.', $min(0));

        $max = self::server()->integerInRange(null, 10);
        $this->assertTrue($max(-5));
        $this->assertSame('The value has to be a whole number lower or equal 10.', $max(11));
    }
}
