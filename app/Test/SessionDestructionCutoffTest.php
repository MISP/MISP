<?php
/**
 * User::checkForSessionDestruction() unit tests.
 *
 * Pure PHPUnit: App, AppModel and RedisTool are stubbed so the real
 * app/Model/User.php can be loaded without the CakePHP bootstrap.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

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
        public $useTable = null;

        public function __construct($id = false, $table = null, $ds = null)
        {
        }
    }
}

if (!class_exists('RedisTool', false)) {
    class RedisTool
    {
        public static $instance = null;

        public static function init()
        {
            if (self::$instance === null) {
                throw new Exception('Redis unavailable');
            }
            return self::$instance;
        }
    }
}

require_once __DIR__ . '/../Model/User.php';

use PHPUnit\Framework\TestCase;

class SessionDestructionCutoffTest extends TestCase
{
    protected function setUp(): void
    {
        RedisTool::$instance = null;
    }

    private function setCutoffs($userCutoff, $allCutoff): void
    {
        RedisTool::$instance = new class ($userCutoff, $allCutoff) {
            private $values;

            public function __construct($userCutoff, $allCutoff)
            {
                $this->values = [$userCutoff, $allCutoff];
            }

            public function mGet(array $keys)
            {
                return $this->values;
            }
        };
    }

    private function check($sessionCreated): bool
    {
        // User::__construct() needs a datasource
        $user = (new ReflectionClass('User'))->newInstanceWithoutConstructor();
        return $user->checkForSessionDestruction(5, $sessionCreated);
    }

    public function testNoCutoff(): void
    {
        $this->setCutoffs(false, false);
        $this->assertFalse($this->check(100));
    }

    public function testOnlyUserCutoff(): void
    {
        $this->setCutoffs('200', false);
        $this->assertTrue($this->check(150));
        $this->assertFalse($this->check(250));
    }

    public function testOnlyGlobalCutoff(): void
    {
        $this->setCutoffs(false, '200');
        $this->assertTrue($this->check(150));
        $this->assertFalse($this->check(250));
    }

    public function testUserCutoffNewerThanGlobalDestroysSessionBetween(): void
    {
        $this->setCutoffs('300', '100');
        $this->assertTrue($this->check(200));
        $this->assertTrue($this->check(50));
        $this->assertFalse($this->check(350));
    }

    public function testGlobalCutoffNewerThanUser(): void
    {
        $this->setCutoffs('100', '300');
        $this->assertTrue($this->check(200));
        $this->assertFalse($this->check(350));
    }

    public function testRedisUnavailableDoesNotDestroy(): void
    {
        $this->assertFalse($this->check(100));
    }
}
