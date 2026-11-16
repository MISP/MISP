<?php
/**
 * OIDC refresh token storage: encrypted at rest when Security.encryption_key is set.
 *
 * Pure PHPUnit: no CakePHP bootstrap, no DB, no IdP. The plugin's private
 * storeMetadata()/readRefreshToken() are driven through reflection.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package = null)
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
    }
}

if (!class_exists('CakeLog', false)) {
    class CakeLog
    {
        public static function write($type, $message)
        {
        }
    }
}

require_once __DIR__ . '/../Lib/Tools/BetterSecurity.php';
require_once __DIR__ . '/../Lib/Tools/EncryptedValue.php';
require_once __DIR__ . '/../Plugin/OidcAuth/Lib/Oidc.php';

use PHPUnit\Framework\TestCase;

class OidcRefreshTokenStorageTest extends TestCase
{
    const TOKEN = 'rt-0123456789-secret-refresh-token';
    const KEY = '0123456789abcdef0123456789abcdef-key';

    /** @var object */
    private $settings;

    /** @var Oidc */
    private $oidc;

    protected function setUp(): void
    {
        Configure::write('Security.encryption_key', null);

        $this->settings = new class {
            public $stored;

            public function setSettingInternal($userId, $setting, $value)
            {
                // UserSetting::beforeSave() serialises the value as JSON
                $this->stored = json_encode($value);
                return true;
            }

            public function getValueForUser($userId, $setting)
            {
                return json_decode($this->stored, true);
            }
        };
        $userModel = new stdClass();
        $userModel->UserSetting = $this->settings;

        $ref = new ReflectionClass('Oidc');
        $this->oidc = $ref->newInstanceWithoutConstructor();
        $prop = $ref->getProperty('User');
        $prop->setAccessible(true);
        $prop->setValue($this->oidc, $userModel);
    }

    private function store()
    {
        $method = new ReflectionMethod('Oidc', 'storeMetadata');
        $method->setAccessible(true);
        $method->invoke($this->oidc, 1, new stdClass(), self::TOKEN);
    }

    private function read(array $userInfo)
    {
        $method = new ReflectionMethod('Oidc', 'readRefreshToken');
        $method->setAccessible(true);
        return $method->invoke($this->oidc, $userInfo);
    }

    public function testKeySetStoredValueDoesNotContainTokenAndRoundTrips(): void
    {
        Configure::write('Security.encryption_key', self::KEY);
        $this->store();
        $this->assertStringNotContainsString(self::TOKEN, $this->settings->stored);
        $userInfo = $this->settings->getValueForUser(1, 'oidc');
        $this->assertSame(self::TOKEN, $this->read($userInfo));
    }

    public function testNoKeyStoresPlaintextAsBefore(): void
    {
        $this->store();
        $userInfo = $this->settings->getValueForUser(1, 'oidc');
        $this->assertSame(self::TOKEN, $userInfo['refresh_token']);
        $this->assertArrayNotHasKey('refresh_token_encrypted', $userInfo);
        $this->assertSame(self::TOKEN, $this->read($userInfo));
    }

    public function testOldPlaintextValueStillReadableWithKeySet(): void
    {
        Configure::write('Security.encryption_key', self::KEY);
        $this->assertSame(self::TOKEN, $this->read(array('refresh_token' => self::TOKEN)));
    }

    public function testWrongKeyIsTreatedAsMissingToken(): void
    {
        Configure::write('Security.encryption_key', self::KEY);
        $this->store();
        $userInfo = $this->settings->getValueForUser(1, 'oidc');

        Configure::write('Security.encryption_key', 'another-key-another-key-another-key-0');
        $this->assertNull($this->read($userInfo));

        Configure::write('Security.encryption_key', null);
        $this->assertNull($this->read($userInfo));
    }

    public function testMissingTokenIsNull(): void
    {
        $this->assertNull($this->read(array('preferred_username' => 'x')));
    }
}
