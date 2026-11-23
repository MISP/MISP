<?php
/**
 * UserSetting::reencryptOidcRefreshTokens(): pure PHPUnit, real model against stubs.
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
require_once __DIR__ . '/../Model/UserSetting.php';

use PHPUnit\Framework\TestCase;

class UserSettingReencryptOidcStub extends UserSetting
{
    public $rows = array();
    public $saved = array();

    public function find($type = 'first', $query = array())
    {
        $out = array();
        foreach ($this->rows as $id => $value) {
            $out[] = array('UserSetting' => array('id' => $id, 'value' => json_decode($value, true)));
        }
        return $out;
    }

    public function save($data = null, $validate = true, $fieldList = array())
    {
        $this->saved[] = $data['id'];
        $this->rows[$data['id']] = $data['value'];
        return true;
    }

    public function decoded($id)
    {
        return json_decode($this->rows[$id], true);
    }
}

class UserSettingReencryptOidcTest extends TestCase
{
    const TOKEN = 'rt-0123456789-secret-refresh-token';
    const OLD = '0123456789abcdef0123456789abcdef-old';
    const NEW = 'fedcba9876543210fedcba9876543210-new';

    private function encrypted($token, $key)
    {
        return base64_encode(EncryptedValue::ENCRYPTED_MAGIC . BetterSecurity::encrypt($token, $key));
    }

    private function model(array $rows)
    {
        $model = (new ReflectionClass('UserSettingReencryptOidcStub'))->newInstanceWithoutConstructor();
        foreach ($rows as $id => $value) {
            $model->rows[$id] = json_encode($value);
        }
        return $model;
    }

    private function read(array $value, $key)
    {
        Configure::write('Security.encryption_key', $key);
        $method = new ReflectionMethod('Oidc', 'readRefreshToken');
        $method->setAccessible(true);
        $oidc = (new ReflectionClass('Oidc'))->newInstanceWithoutConstructor();
        return $method->invoke($oidc, $value);
    }

    public function testEncryptedIsReencryptedUnderNewKey(): void
    {
        $model = $this->model(array(1 => array('refresh_token' => $this->encrypted(self::TOKEN, self::OLD), 'refresh_token_encrypted' => true)));
        $this->assertTrue($model->reencryptOidcRefreshTokens(self::OLD, self::NEW));
        $value = $model->decoded(1);
        $this->assertTrue($value['refresh_token_encrypted']);
        $this->assertStringNotContainsString(self::TOKEN, $model->rows[1]);
        $this->assertSame(self::TOKEN, $this->read($value, self::NEW));
        $this->assertNull($this->read($value, self::OLD));
    }

    public function testEmptyNewKeyStoresPlaintextAndDropsFlag(): void
    {
        $model = $this->model(array(1 => array('refresh_token' => $this->encrypted(self::TOKEN, self::OLD), 'refresh_token_encrypted' => true)));
        $model->reencryptOidcRefreshTokens(self::OLD, '');
        $this->assertSame(array('refresh_token' => self::TOKEN), $model->decoded(1));
    }

    public function testPlaintextIsEncryptedWhenNewKeySet(): void
    {
        $model = $this->model(array(1 => array('refresh_token' => self::TOKEN)));
        $model->reencryptOidcRefreshTokens(null, self::NEW);
        $value = $model->decoded(1);
        $this->assertTrue($value['refresh_token_encrypted']);
        $this->assertSame(self::TOKEN, $this->read($value, self::NEW));
    }

    public function testUnchangedRowsAreNotSavedAndNothingToDoIsTrue(): void
    {
        $model = $this->model(array(1 => array('refresh_token' => self::TOKEN), 2 => array('other' => 'x')));
        $this->assertTrue($model->reencryptOidcRefreshTokens(self::OLD, ''));
        $this->assertSame(array(), $model->saved);
    }

    public function testWrongOldKeyThrows(): void
    {
        $model = $this->model(array(7 => array('refresh_token' => $this->encrypted(self::TOKEN, self::OLD), 'refresh_token_encrypted' => true)));
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('#7');
        $model->reencryptOidcRefreshTokens('wrong-key-wrong-key-wrong-key-wrong-0', self::NEW);
    }

    public function testOtherKeysArePreserved(): void
    {
        $model = $this->model(array(1 => array('validity_check_timestamp' => 123, 'sub' => 'abc', 'refresh_token' => self::TOKEN)));
        $model->reencryptOidcRefreshTokens(null, self::NEW);
        $value = $model->decoded(1);
        $this->assertSame(123, $value['validity_check_timestamp']);
        $this->assertSame('abc', $value['sub']);
    }
}
