<?php
/**
 * LinOTPAuthenticate TLS verification default.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no network: HttpSocket is stubbed to
 * record its constructor params and to answer with a non-200 so the plugin
 * gives up straight after the request.
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

        public static function reset()
        {
            self::$values = array();
        }
    }
}

if (!class_exists('CakeLog', false)) {
    class CakeLog
    {
        public static function __callStatic($name, $arguments)
        {
        }
    }
}

if (!class_exists('SocketException', false)) {
    class SocketException extends RuntimeException
    {
    }
}

if (!class_exists('BaseAuthenticate', false)) {
    class BaseAuthenticate
    {
        public $settings = array('userModel' => 'User');

        protected function _findUser($username, $password = null)
        {
            return false;
        }
    }
}

if (!class_exists('CakeRequest', false)) {
    class CakeRequest
    {
        public $data = array();
    }
}

if (!class_exists('HttpSocket', false)) {
    class HttpSocket
    {
        public static $params = null;

        public function __construct($params = array())
        {
            self::$params = $params;
        }

        public function post($uri = null, $data = array())
        {
            return (object)array('code' => '500');
        }
    }
}

require_once __DIR__ . '/../Plugin/LinOTPAuth/Controller/Component/Auth/LinOTPAuthenticate.php';

use PHPUnit\Framework\TestCase;

class LinOTPAuthenticateTlsTest extends TestCase
{
    protected function setUp(): void
    {
        Configure::reset();
        Configure::write('LinOTPAuth.baseUrl', 'https://linotp.example');
        HttpSocket::$params = null;
    }

    private function login(): void
    {
        $request = new CakeRequest();
        $request->data = array('User' => array('email' => 'a@example.com', 'password' => 'secret'));
        $auth = new LinOTPAuthenticate();
        $this->assertFalse($auth->getUser($request));
        $this->assertIsArray(HttpSocket::$params, 'LinOTP was not queried');
    }

    private function assertVerifying(): void
    {
        $this->assertTrue(HttpSocket::$params['ssl_verify_peer']);
        $this->assertTrue(HttpSocket::$params['ssl_verify_peer_name']);
        $this->assertFalse(HttpSocket::$params['ssl_allow_self_signed']);
    }

    public function testUnsetVerifysslVerifiesCertificates(): void
    {
        $this->login();
        $this->assertVerifying();
    }

    public function testNullVerifysslVerifiesCertificates(): void
    {
        Configure::write('LinOTPAuth.verifyssl', null);
        $this->login();
        $this->assertVerifying();
    }

    public function testVerifysslTrueVerifiesCertificates(): void
    {
        Configure::write('LinOTPAuth.verifyssl', true);
        $this->login();
        $this->assertVerifying();
    }

    public function testExplicitFalseStillOptsOut(): void
    {
        foreach (array(false, 0, '0') as $off) {
            Configure::write('LinOTPAuth.verifyssl', $off);
            HttpSocket::$params = null;
            $this->login();
            $this->assertFalse(HttpSocket::$params['ssl_verify_peer'], var_export($off, true));
            $this->assertFalse(HttpSocket::$params['ssl_verify_peer_name'], var_export($off, true));
            $this->assertTrue(HttpSocket::$params['ssl_allow_self_signed'], var_export($off, true));
        }
    }
}
