<?php
/**
 * SysLogLogableBehavior shell-identity unit tests.
 *
 * Pure PHPUnit, no DB, no CakePHP bootstrap; every framework touchpoint
 * the behaviour has is stubbed below. Each test runs in its own process
 * because the behaviour decides "shell or web" on the CAKEPHP_SHELL
 * constant, which a process can define only once, and because the
 * behaviour file must load against THESE stubs (it calls App::import()
 * at load, which the guarded stubs other test files share do not offer).
 *
 * What is under test: rows the default audit engine writes from a
 * console shell. The behaviour is a ClassRegistry singleton whose
 * setup() runs for every model that attaches it, so an identity set
 * once at startup was overwritten by the first lazy model load and the
 * rest of the session logged as SYSTEM. A shell now publishes the
 * account it acts as through setShellUser(); the behaviour resolves it
 * at write time and says "via CLI" in the description, the way an
 * AuditLog row carries request_type = CLI. A shell that publishes
 * nothing - every background job - keeps logging as SYSTEM, and a web
 * request keeps taking the session user with no marker.
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../Vendor/autoload.php';

// -------- framework stubs (guarded; in the isolated process they are the only ones) --------

if (!class_exists('App', false)) {
    class App
    {
        public static function uses($class, $package)
        {
        }

        public static function import($type, $name)
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

if (!class_exists('AuthComponent', false)) {
    class AuthComponent
    {
        public static $sessionUser = null;

        public static function user($key = null)
        {
            return self::$sessionUser;
        }
    }
}

if (!class_exists('Model', false)) {
    class Model
    {
        public $alias;
        public $name;
        public $primaryKey = 'id';
        public $displayField = 'name';
        public $id = null;
        public $insertId = null;
        public $data = array();
        public $logableAction = null;

        public function __construct($alias, $displayField = 'name')
        {
            $this->alias = $alias;
            $this->name = $alias;
            $this->displayField = $displayField;
        }

        public function schema()
        {
            return array('id' => array(), 'name' => array(), 'email' => array());
        }

        public function field($name)
        {
            return isset($this->data[$this->alias][$name]) ? $this->data[$this->alias][$name] : null;
        }
    }
}

if (!class_exists('SysLogLogableTestLog', false)) {
    /** Captures what the behaviour would have written to the logs table. */
    class SysLogLogableTestLog
    {
        public $rows = array();
        private $pending = null;

        public function schema()
        {
            return array(
                'id' => array(), 'title' => array(), 'created' => array(), 'model' => array(),
                'model_id' => array(), 'action' => array(), 'user_id' => array(), 'change' => array(),
                'email' => array(), 'org' => array(), 'description' => array(), 'ip' => array(),
            );
        }

        public function create($data)
        {
            $this->pending = $data;
        }

        public function saveOrFailSilently($data = null, $options = array())
        {
            $this->rows[] = $this->pending['Log'];
            $this->pending = null;
            return true;
        }
    }
}

if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $instances = array();

        public static function init($name)
        {
            if (!isset(self::$instances[$name])) {
                self::$instances[$name] = new Model($name);
            }
            return self::$instances[$name];
        }

        public static function reset()
        {
            self::$instances = array();
        }
    }
}

if (!class_exists('LogableBehavior', false)) {
    /** The Assets-plugin parent, reduced to the state the child reads. */
    class LogableBehavior
    {
        public $user = null;
        public $UserModel = false;
        public $Log = null;
        public $settings = array();
        public $schema = array();
        public $old = array();
        public $defaults = array(
            'enabled' => true,
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'list',
            'description_ids' => true,
            'skip' => array(),
            'ignore' => array(),
            'classField' => 'model',
            'foreignKey' => 'model_id',
        );

        public function __construct()
        {
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

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class SysLogLogableShellIdentityTest extends TestCase
{
    /** @var SysLogLogableTestLog */
    private $log;

    /** @var SysLogLogableBehavior */
    private $behavior;

    private static $operator = array(
        'id' => 195,
        'email' => 'foo@aaaaaa.aaa',
        'Organisation' => array('name' => 'komplett.no'),
        'Role' => array('perm_site_admin' => 0),
    );

    protected function setUp(): void
    {
        require_once __DIR__ . '/../Plugin/SysLogLogable/Model/Behavior/SysLogLogableBehavior.php';
        Configure::reset();
        ClassRegistry::reset();
        AuthComponent::$sessionUser = null;
        $this->log = new SysLogLogableTestLog();
        ClassRegistry::$instances['Log'] = $this->log;
        ClassRegistry::$instances['User'] = new Model('User', 'email');
        $this->behavior = new SysLogLogableBehavior();
        SysLogLogableBehavior::setShellUser(null);
    }

    private function attach($alias, $displayField = 'name')
    {
        $model = new Model($alias, $displayField);
        $this->behavior->setup($model, array('change' => 'full'));
        return $model;
    }

    private function saveThrough(Model $model, $id, array $fields, $created = false)
    {
        $model->id = $id;
        $model->data = array($model->alias => array_merge(array('id' => $id), $fields));
        $this->behavior->old = array();
        $this->behavior->afterSave($model, $created);
        $this->assertNotEmpty($this->log->rows, 'no row was written');
        return end($this->log->rows);
    }

    private function deleteThrough(Model $model, $id, array $fields)
    {
        $model->id = $id;
        $model->data = array($model->alias => array_merge(array('id' => $id), $fields));
        $this->behavior->_saveLog($model, array('Log' => array(
            'description' => $model->alias . ' "' . $fields['name'] . '" (' . $id . ') deleted',
            'action' => 'delete',
        )));
        return end($this->log->rows);
    }

    // ---- shell, no published identity: every background job ----

    public function testShellWithNoPublishedUserLogsAsSystemWithoutMarker()
    {
        define('CAKEPHP_SHELL', true);
        $tag = $this->attach('Tag');

        $row = $this->saveThrough($tag, 8205, array('name' => 'v44-probe-tag'), true);

        $this->assertSame(0, $row['user_id']);
        $this->assertSame('SYSTEM', $row['email']);
        $this->assertSame('SYSTEM', $row['org']);
        $this->assertSame('Tag "v44-probe-tag" (8205) added by User "SYSTEM" (0).', $row['description']);
        $this->assertStringNotContainsString('via CLI', $row['description']);
    }

    // ---- shell acting as a user ----

    public function testShellRowCarriesPublishedUserAndCliMarker()
    {
        define('CAKEPHP_SHELL', true);
        SysLogLogableBehavior::setShellUser(self::$operator);
        $tag = $this->attach('Tag');

        $row = $this->saveThrough($tag, 8205, array('name' => 'v44-probe-tag'), true);

        $this->assertSame(195, $row['user_id']);
        $this->assertSame('foo@aaaaaa.aaa', $row['email'], 'identity columns carry no marker');
        $this->assertSame('komplett.no', $row['org']);
        $this->assertSame(
            'Tag "v44-probe-tag" (8205) added by User "foo@aaaaaa.aaa" (195) via CLI.',
            $row['description']
        );
    }

    public function testIdentityPublishedAfterModelsAttachedStillApplies()
    {
        define('CAKEPHP_SHELL', true);
        // The shell resolves its user through the User model before it can
        // publish anything, so User (and its associations) attach first.
        $user = $this->attach('User', 'email');
        $tag = $this->attach('Tag');
        SysLogLogableBehavior::setShellUser(self::$operator);

        $row = $this->saveThrough($tag, 8205, array('name' => 'v44-probe-tag'), true);

        $this->assertSame(195, $row['user_id']);
        $this->assertStringEndsWith('(195) via CLI.', $row['description']);
    }

    public function testLazyModelAttachMidSessionDoesNotResetIdentity()
    {
        define('CAKEPHP_SHELL', true);
        SysLogLogableBehavior::setShellUser(self::$operator);
        $tag = $this->attach('Tag');

        $first = $this->saveThrough($tag, 8205, array('name' => 'v44-probe-tag'), false);
        $this->assertSame(195, $first['user_id']);

        // What happened live: Log::afterSave fired a workflow trigger that
        // loaded the Workflow model, and Tag::delete loaded TagCollectionTag;
        // each attach re-ran setup() on the shared singleton.
        $this->attach('Workflow');
        $this->attach('TagCollectionTag');

        $second = $this->deleteThrough($tag, 8205, array('name' => 'v44-probe-tag'));

        $this->assertSame(195, $second['user_id'], 'the delete after a lazy attach flipped to SYSTEM');
        $this->assertSame('foo@aaaaaa.aaa', $second['email']);
        $this->assertSame(
            'Tag "v44-probe-tag" (8205) deleted by User "foo@aaaaaa.aaa" (195) via CLI.',
            $second['description']
        );
    }

    public function testClearingThePublishedUserRevertsToSystem()
    {
        define('CAKEPHP_SHELL', true);
        SysLogLogableBehavior::setShellUser(self::$operator);
        $tag = $this->attach('Tag');
        SysLogLogableBehavior::setShellUser(null);

        $row = $this->saveThrough($tag, 8205, array('name' => 'v44-probe-tag'), true);

        $this->assertSame(0, $row['user_id']);
        $this->assertSame('SYSTEM', $row['email']);
        $this->assertStringNotContainsString('via CLI', $row['description']);
    }

    public function testPublishedUserIsNormalisedToTheThreeFieldsTheRowNeeds()
    {
        define('CAKEPHP_SHELL', true);
        SysLogLogableBehavior::setShellUser(array('id' => '7', 'email' => 'x@y.z'));
        $tag = $this->attach('Tag');

        $row = $this->saveThrough($tag, 1, array('name' => 't'), true);

        $this->assertSame(7, $row['user_id']);
        $this->assertSame('x@y.z', $row['email']);
        $this->assertSame('', $row['org'], 'a missing organisation is an empty name, not a notice');
    }

    // ---- web request: unchanged ----

    public function testWebRequestTakesSessionUserWithoutMarkerEvenIfShellUserWasPublished()
    {
        // CAKEPHP_SHELL deliberately undefined in this process.
        AuthComponent::$sessionUser = array(
            'id' => 1,
            'email' => 'admin@admin.test',
            'Organisation' => array('name' => 'Iglocska'),
        );
        SysLogLogableBehavior::setShellUser(self::$operator);
        $tag = $this->attach('Tag');

        $row = $this->saveThrough($tag, 8205, array('name' => 'v44-probe-tag'), true);

        $this->assertSame(1, $row['user_id']);
        $this->assertSame('admin@admin.test', $row['email']);
        $this->assertSame(
            'Tag "v44-probe-tag" (8205) added by User "admin@admin.test" (1).',
            $row['description']
        );
    }

    public function testWebRequestWithNoSessionLogsAsSystem()
    {
        $tag = $this->attach('Tag');

        $row = $this->saveThrough($tag, 8205, array('name' => 'v44-probe-tag'), true);

        $this->assertSame(0, $row['user_id']);
        $this->assertSame('SYSTEM', $row['email']);
        $this->assertSame('Tag "v44-probe-tag" (8205) added by User "SYSTEM" (0).', $row['description']);
    }
}
