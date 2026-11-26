<?php
/**
 * LdapAuthenticate provisioning of an existing, disabled MISP user.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB, no LDAP server: provisionUser()
 * is driven by reflection with the user model replaced by a recorder.
 * ApacheAuthenticate is not covered: its whole flow lives in authenticate(),
 * behind ldap_connect()/ldap_bind() and die().
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

        public static function write($key, $value)
        {
            self::$values[$key] = $value;
        }
    }
}

if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $instances = array();

        public static function init($name)
        {
            return self::$instances[$name];
        }

        public static function reset()
        {
            self::$instances = array();
        }
    }
}

if (!class_exists('CakeLog', false)) {
    class CakeLog
    {
        public static function __callStatic($name, $args)
        {
        }
    }
}

if (!class_exists('UnauthorizedException', false)) {
    class UnauthorizedException extends Exception
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

if (!function_exists('__')) {
    function __($string)
    {
        $args = func_get_args();
        $format = array_shift($args);
        return empty($args) ? $format : vsprintf($format, $args);
    }
}

require_once __DIR__ . '/../Plugin/LdapAuth/Controller/Component/Auth/LdapAuthenticate.php';

class LdapAuthDisabledUserFakeModel
{
    public $row;
    public $saved = array();

    public function save($data, $validate = true)
    {
        $this->saved[] = $data;
        $this->row = $data;
        return true;
    }
}

class LdapAuthDisabledUserTestAuth extends LdapAuthenticate
{
    public $model;

    protected function _findUser($username, $password = null)
    {
        return $this->model->row;
    }
}

use PHPUnit\Framework\TestCase;

class LdapAuthDisabledUserTest extends TestCase
{
    private $model;
    private $auth;

    protected function setUp(): void
    {
        $this->model = new LdapAuthDisabledUserFakeModel();
        ClassRegistry::$instances['User'] = $this->model;
        // The constructor reads LDAP_* constants the ldap extension may lack.
        $this->auth = (new ReflectionClass('LdapAuthDisabledUserTestAuth'))->newInstanceWithoutConstructor();
        $this->auth->model = $this->model;
    }

    protected function tearDown(): void
    {
        ClassRegistry::reset();
    }

    private function configure(array $extra = array())
    {
        $conf = array_merge(array(
            'ldapEmailField' => array('mail'),
            'updateUser' => true,
            'unblock' => false,
            'ldapDefaultOrgId' => 2,
            'ldapDefaultRoleId' => 3,
            'ldapOrgField' => null,
            'ldapOrgGroupMapping' => null,
            'ldapRoleField' => null,
            'ldapRoleGroupMapping' => null,
        ), $extra);
        $property = new ReflectionProperty('LdapAuthenticate', 'conf');
        $property->setAccessible(true);
        $property->setValue(null, $conf);
    }

    private function provision()
    {
        $method = new ReflectionMethod('LdapAuthenticate', 'provisionUser');
        $method->setAccessible(true);
        $entry = array(array('mail' => array('alice@example.com')));
        return $method->invoke($this->auth, null, $entry, 'alice@example.com');
    }

    private function existingUser($disabled)
    {
        $this->model->row = array(
            'id' => 7,
            'email' => 'alice@example.com',
            'org_id' => 9,
            'role_id' => 9,
            'disabled' => $disabled,
        );
    }

    public function testDisabledUserIsRefusedAndStaysDisabledByDefault(): void
    {
        $this->configure();
        $this->existingUser(1);
        try {
            $this->provision();
            $this->fail('A disabled user must not be logged in.');
        } catch (UnauthorizedException $e) {
            $this->assertTrue(true);
        }
        foreach ($this->model->saved as $saved) {
            $this->assertEquals(1, $saved['disabled']);
        }
        $this->assertEquals(1, $this->model->row['disabled']);
    }

    public function testDisabledUserStillGetsRoleAndOrgUpdateWhenRefused(): void
    {
        $this->configure();
        $this->existingUser(1);
        try {
            $this->provision();
        } catch (UnauthorizedException $e) {
        }
        $this->assertCount(1, $this->model->saved);
        $this->assertEquals(3, $this->model->saved[0]['role_id']);
        $this->assertEquals(2, $this->model->saved[0]['org_id']);
    }

    public function testDisabledUserIsReenabledWhenUnblockIsSet(): void
    {
        $this->configure(array('unblock' => true));
        $this->existingUser(1);
        $user = $this->provision();
        $this->assertEquals(0, $this->model->saved[0]['disabled']);
        $this->assertEquals(0, $user['disabled']);
    }

    public function testEnabledUserIsUpdatedAndReturned(): void
    {
        $this->configure();
        $this->existingUser(0);
        $user = $this->provision();
        $this->assertCount(1, $this->model->saved);
        $this->assertEquals(0, $this->model->saved[0]['disabled']);
        $this->assertEquals(3, $user['role_id']);
    }
}
