<?php
/**
 * User::forgot() reset-link base URL unit tests.
 *
 * Pure PHPUnit: App, AppModel, Configure, RedisTool and RandomTool are
 * stubbed so the real app/Model/User.php can be loaded without the CakePHP
 * bootstrap.
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

if (!class_exists('Configure', false)) {
    class Configure
    {
        private static $values = array();

        public static function write($key, $value)
        {
            self::$values[$key] = $value;
        }

        public static function read($key)
        {
            return isset(self::$values[$key]) ? self::$values[$key] : null;
        }

        public static function check($key)
        {
            return isset(self::$values[$key]);
        }

        public static function reset()
        {
            self::$values = array();
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

if (!class_exists('RandomTool', false)) {
    class RandomTool
    {
        public static function random_str($crypto = true, $length = 20)
        {
            return str_repeat('a', $length);
        }
    }
}

if (!function_exists('__')) {
    function __($singular)
    {
        return $singular;
    }
}

require_once __DIR__ . '/../Model/User.php';

use PHPUnit\Framework\TestCase;

class PasswordResetBaseurlTestUser extends User
{
    public $sent = [];
    public $logged = [];

    public function __construct($id = false, $table = null, $ds = null)
    {
    }

    public function find($type = 'first', $query = array())
    {
        return ['User' => ['id' => 7, 'email' => 'victim@example.com']];
    }

    public function sendEmail($user, $body, $bodyNoEnc = false, $subject = '', $replyToUser = false)
    {
        $this->sent[] = $body;
        return true;
    }

    public function log($msg, $type = LOG_ERR, $scope = null)
    {
        $this->logged[] = $msg;
        return true;
    }
}

class PasswordResetBaseurlTest extends TestCase
{
    private $redis;

    protected function setUp(): void
    {
        Configure::reset();
        $this->redis = new class {
            public $tokens = [];

            public function set($key, $value, $options = null)
            {
                $this->tokens[$key] = $value;
                return true;
            }
        };
        RedisTool::$instance = $this->redis;
    }

    public function testBaseurlDerivedFromRequestSendsNothing(): void
    {
        Configure::write('MISP.baseurl', 'http://evil.example');
        Configure::write('BaseurlFromRequest', true);
        $user = new PasswordResetBaseurlTestUser();
        $this->assertFalse($user->forgot('victim@example.com', '203.0.113.9'));
        $this->assertSame([], $user->sent);
        $this->assertSame([], $this->redis->tokens);
        $this->assertCount(1, $user->logged);
        $this->assertStringContainsString('MISP.external_baseurl', $user->logged[0]);
    }

    public function testConfiguredBaseurlIsUsed(): void
    {
        Configure::write('MISP.baseurl', 'https://misp.example');
        $user = new PasswordResetBaseurlTestUser();
        $this->assertTrue($user->forgot('victim@example.com', '203.0.113.9'));
        $this->assertCount(1, $user->sent);
        $this->assertStringContainsString('https://misp.example/users/password_reset/', $user->sent[0]);
        $this->assertCount(1, $this->redis->tokens);
    }

    public function testExternalBaseurlIsPreferred(): void
    {
        Configure::write('MISP.baseurl', 'https://misp.example');
        Configure::write('MISP.external_baseurl', 'https://public.example');
        $user = new PasswordResetBaseurlTestUser();
        $this->assertTrue($user->forgot('victim@example.com', '203.0.113.9'));
        $this->assertStringContainsString('https://public.example/users/password_reset/', $user->sent[0]);
        $this->assertStringNotContainsString('https://misp.example', $user->sent[0]);
    }

    public function testExternalBaseurlWinsOverRequestDerivedBaseurl(): void
    {
        Configure::write('MISP.baseurl', 'http://evil.example');
        Configure::write('BaseurlFromRequest', true);
        Configure::write('MISP.external_baseurl', 'https://public.example');
        $user = new PasswordResetBaseurlTestUser();
        $this->assertTrue($user->forgot('victim@example.com', '203.0.113.9'));
        $this->assertStringContainsString('https://public.example/users/password_reset/', $user->sent[0]);
    }

    public function testEmptyExternalBaseurlFallsBackToBaseurl(): void
    {
        Configure::write('MISP.baseurl', 'https://misp.example');
        Configure::write('MISP.external_baseurl', '');
        $user = new PasswordResetBaseurlTestUser();
        $this->assertTrue($user->forgot('victim@example.com', '203.0.113.9'));
        $this->assertStringContainsString('https://misp.example/users/password_reset/', $user->sent[0]);
    }

    public function testNoBaseurlAtAllSendsNothing(): void
    {
        $user = new PasswordResetBaseurlTestUser();
        $this->assertFalse($user->forgot('victim@example.com', '203.0.113.9'));
        $this->assertSame([], $user->sent);
    }
}
