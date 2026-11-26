<?php
/**
 * CertificateAuthenticate honours the web server's client certificate verdict.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB: framework classes are stubbed.
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

        public static function read($key)
        {
            return isset(self::$values[$key]) ? self::$values[$key] : null;
        }

        public static function check($key)
        {
            return isset(self::$values[$key]);
        }

        public static function write($key, $value)
        {
            self::$values[$key] = $value;
        }

        public static function reset()
        {
            self::$values = array();
        }
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

require_once __DIR__ . '/../Plugin/CertAuth/Controller/Component/Auth/CertificateAuthenticate.php';

use PHPUnit\Framework\TestCase;

class CertificateAuthenticateVerifyTest extends TestCase
{
    private $serverBackup;
    private $configBackup = array();
    private $keys = array('CertAuth.ca', 'CertAuth.caId', 'CertAuth.map', 'CertAuth.mapCa');

    protected function setUp(): void
    {
        $this->serverBackup = $_SERVER;
        foreach ($this->keys as $key) {
            $this->configBackup[$key] = Configure::read($key);
        }
        unset($_SERVER['SSL_CLIENT_VERIFY']);
        $_SERVER['SSL_CLIENT_I_DN'] = '/O=Trusted CA/CN=issuer';
        $_SERVER['SSL_CLIENT_S_DN'] = '/O=Org/emailAddress=user@example.com';
        Configure::write('CertAuth.ca', array('Trusted CA'));
        Configure::write('CertAuth.caId', 'O');
        Configure::write('CertAuth.map', array('O' => 'org', 'emailAddress' => 'email'));
        Configure::write('CertAuth.mapCa', null);
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->serverBackup;
        foreach ($this->configBackup as $key => $value) {
            Configure::write($key, $value);
        }
        $this->setStatic('ca', null);
        $this->setStatic('client', null);
        $this->setStatic('user', null);
    }

    private function setStatic($name, $value)
    {
        $property = new ReflectionProperty('CertificateAuthenticate', $name);
        $property->setAccessible(true);
        $property->setValue(null, $value);
    }

    private function client()
    {
        new CertificateAuthenticate();
        $property = new ReflectionProperty('CertificateAuthenticate', 'client');
        $property->setAccessible(true);
        return $property->getValue();
    }

    public function testVerifySuccessYieldsClient()
    {
        $_SERVER['SSL_CLIENT_VERIFY'] = 'SUCCESS';
        $client = $this->client();
        $this->assertSame('user@example.com', $client['email']);
    }

    public function testVerifyFailedYieldsNoClient()
    {
        $_SERVER['SSL_CLIENT_VERIFY'] = 'FAILED';
        $this->assertFalse($this->client());
    }

    public function testVerifyGenerousYieldsNoClient()
    {
        $_SERVER['SSL_CLIENT_VERIFY'] = 'GENEROUS';
        $this->assertFalse($this->client());
    }

    public function testVerifyAbsentYieldsClient()
    {
        $client = $this->client();
        $this->assertSame('user@example.com', $client['email']);
    }

    public function testCaMismatchYieldsNoClient()
    {
        $_SERVER['SSL_CLIENT_VERIFY'] = 'SUCCESS';
        $_SERVER['SSL_CLIENT_I_DN'] = '/O=Rogue CA/CN=issuer';
        $this->assertFalse($this->client());
    }
}
