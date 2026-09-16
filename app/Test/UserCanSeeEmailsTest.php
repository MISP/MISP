<?php
/**
 * User::canSeeEmails() unit tests (V25 contract).
 *
 * Pure PHPUnit - follows the convention used by every other test under
 * app/Test/: no CakePHP bootstrap, no DB. The User model needs `App` and
 * `AppModel` to exist before it can be defined, and the predicate reads
 * `Configure`; all three are stubbed here.
 *
 * The point of pinning this is that three call sites now share it -
 * DashboardsController::listTemplates, NewUsersWidget and
 * UserContributionToplistWidget - after each carried its own copy (and
 * listTemplates carried a fourth, different rule gated on the render mode).
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

        public static function reset()
        {
            self::$values = array();
        }
    }
}

require_once __DIR__ . '/../Model/User.php';

use PHPUnit\Framework\TestCase;

class UserCanSeeEmailsTest extends TestCase
{
    protected function setUp(): void
    {
        Configure::reset();
    }

    // -------- default posture: setting off, ordinary user --------

    public function testOrdinaryUserIsRedactedByDefault(): void
    {
        // Security.disclose_user_emails ships as false and is nullable, so
        // "unset" must behave exactly like "off".
        $this->assertFalse(User::canSeeEmails(array('Role' => array('perm_site_admin' => 0))));
        Configure::write('Security.disclose_user_emails', false);
        $this->assertFalse(User::canSeeEmails(array('Role' => array('perm_site_admin' => 0))));
    }

    public function testOrgAdminIsRedactedByDefault(): void
    {
        // perm_admin is deliberately not enough - the setting's own text is
        // about showing addresses to "non site-admin users".
        $this->assertFalse(User::canSeeEmails(array(
            'Role' => array('perm_site_admin' => 0, 'perm_admin' => 1),
        )));
    }

    // -------- the two ways to be allowed --------

    public function testSiteAdminAlwaysSees(): void
    {
        Configure::write('Security.disclose_user_emails', false);
        $this->assertTrue(User::canSeeEmails(array('Role' => array('perm_site_admin' => 1))));
    }

    public function testSettingOptsEveryoneIn(): void
    {
        Configure::write('Security.disclose_user_emails', true);
        $this->assertTrue(User::canSeeEmails(array('Role' => array('perm_site_admin' => 0))));
    }

    // -------- the string forms the settings layer actually stores --------

    /**
     * Server settings round-trip through the database as '0'/'1' strings, and
     * the two call sites this replaced disagreed on the idiom - one wrote
     * `!Configure::read(...)`, the other `empty(Configure::read(...))`. Pin
     * that every stored form agrees, so consolidating them changed nothing.
     */
    public function testStringAndNumericFormsAgree(): void
    {
        $ordinary = array('Role' => array('perm_site_admin' => 0));
        foreach (array('0', 0, false, null, '') as $off) {
            Configure::write('Security.disclose_user_emails', $off);
            $this->assertFalse(User::canSeeEmails($ordinary), var_export($off, true));
        }
        foreach (array('1', 1, true) as $on) {
            Configure::write('Security.disclose_user_emails', $on);
            $this->assertTrue(User::canSeeEmails($ordinary), var_export($on, true));
        }
    }

    // -------- malformed / partial user arrays fail closed --------

    public function testMissingRoleFailsClosed(): void
    {
        Configure::write('Security.disclose_user_emails', false);
        $this->assertFalse(User::canSeeEmails(array()));
        $this->assertFalse(User::canSeeEmails(array('Role' => array())));
        $this->assertFalse(User::canSeeEmails(array('id' => 5)));
    }
}
