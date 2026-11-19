<?php
/**
 * Event::sendAlertEmail() alert e-mail fetch tests.
 *
 * The event handed to an alert e-mail is fetched with the recipient's own user
 * context so that every ACL is respected, but the result only depends on the
 * recipient's org and role, not on the recipient itself. sendAlertEmail() used
 * to issue that full fetch once per recipient, so an instance with 500
 * autoalert users performed 500 complete event fetches for a single alert.
 * These tests pin down the grouping:
 *   - one fetch per distinct (org_id, perm_site_admin, perm_audit) context;
 *   - every recipient still receives the event as fetched for their OWN
 *     context (an over-eager grouping would leak another context's event);
 *   - the per-user publish filter is still evaluated per recipient.
 *
 * Pure PHPUnit, no CakePHP bootstrap, no DB - the convention used by every
 * other test under app/Test/ (see CollectionCaptureTest / UserCanSeeEmailsTest).
 * The framework stubs are guarded with class_exists so a full-suite run shares
 * whichever file loaded them first; the AppModel stub below is a superset of
 * the other stubs' contracts for that reason.
 */

require_once __DIR__ . '/../Vendor/autoload.php';

// -------- framework stubs (must exist BEFORE Event.php loads) --------

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

if (!class_exists('EventAlertEmailFakeModel', false)) {
    class EventAlertEmailFakeModel
    {
        public $responses = array();

        public function find($type, $opts = array())
        {
            return empty($this->responses) ? array() : array_shift($this->responses);
        }
    }
}

// NB: ClassRegistry is also stubbed by CollectionCaptureTest and
// PewPewMapWidgetTest. All of them guard with class_exists(), so in a
// full-suite run whichever loads first wins for everyone - we therefore keep
// the same contract: a public static $instances plus an init() that
// auto-creates a find()/responses fake for any unregistered name (never null).
// Our own NotificationLog double is pre-registered into $instances before
// init() is reached.
if (!class_exists('ClassRegistry', false)) {
    class ClassRegistry
    {
        public static $instances = array();

        public static function init($name)
        {
            if (!isset(self::$instances[$name])) {
                self::$instances[$name] = new EventAlertEmailFakeModel();
            }
            return self::$instances[$name];
        }

        public static function reset()
        {
            self::$instances = array();
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

if (!class_exists('AppModel', false)) {
    class AppModel
    {
        public $alias = 'Event';
        public $useTable = null;
        public $id = false;
        public $data = array();
        public $validationErrors = array();

        public function __construct($id = false, $table = null, $ds = null)
        {
        }

        public function create($data = array())
        {
            $this->id = false;
        }

        public function save($data = null, $validate = true, $fieldList = array())
        {
            return true;
        }

        public function find($type, $options = array())
        {
            return array();
        }
    }
}

require_once __DIR__ . '/../Model/Event.php';

use PHPUnit\Framework\TestCase;

/**
 * Publish filter double: rejects the user ids it was told to reject.
 */
class EventAlertEmailUserSetting
{
    public $rejectedUserIds = array();

    public function checkPublishFilter(array $user, array $event)
    {
        return !in_array($user['id'], $this->rejectedUserIds);
    }
}

/**
 * User model double: returns the configured recipients and records the e-mails.
 */
class EventAlertEmailUser
{
    public $UserSetting;
    public $usersWithAccess = array();
    public $sentEmails = array();

    public function __construct()
    {
        $this->UserSetting = new EventAlertEmailUserSetting();
    }

    public function getUsersWithAccess(array $owners, $distribution, $sharing_group_id = 0, array $userConditions = array())
    {
        return $this->usersWithAccess;
    }

    public function sendEmail($user, $body, $bodyNoEnc = false, $subject = null)
    {
        $this->sentEmails[] = array('user_id' => $user['User']['id'], 'body' => $body);
        return true;
    }
}

class EventAlertEmailNotificationLog
{
    public function check($orgId, $action)
    {
        return true;
    }
}

/**
 * Event double: find() returns the alerted event, fetchEvent() records the ACL
 * context it was called with and tags the returned event with it, and
 * prepareAlertEmail() hands that tag over as the e-mail body so that each sent
 * e-mail can be traced back to the fetch it was built from.
 */
class EventAlertEmailTestableEvent extends Event
{
    public $User;
    public $Job;
    public $NotificationLog;
    public $event = array();
    public $fetchedContexts = array();

    public function find($type, $options = array())
    {
        return $this->event;
    }

    public function fetchEvent($user, $options = array(), $useCache = false)
    {
        $context = $user['org_id'] . '-' . $user['Role']['perm_site_admin'] . '-' . $user['Role']['perm_audit'];
        $this->fetchedContexts[] = $context;
        return array(array('Event' => array('id' => 1, 'info' => 'alert me'), 'context' => $context));
    }

    public function prepareAlertEmail(array $event, array $user, $oldpublish = null)
    {
        return $event['context'];
    }
}

class EventAlertEmailTest extends TestCase
{
    public function testEventIsFetchedOncePerAclContext()
    {
        $event = $this->createEventModel();
        $event->User->usersWithAccess = array(
            $this->user(1, 1, 0),
            $this->user(2, 1, 0),
            $this->user(3, 2, 0),
            $this->user(4, 1, 1),
            $this->user(5, 1, 0, 1),
        );

        $event->sendAlertEmail(1, $this->senderUser());

        // One fetch per distinct org / site admin / auditor context, in the
        // order the contexts are first seen - not one fetch per recipient.
        $this->assertSame(array('1-0-0', '2-0-0', '1-1-0', '1-0-1'), $event->fetchedContexts);
        // Every recipient is served the event fetched for their own context.
        $this->assertSame(
            array(
                array('user_id' => 1, 'body' => '1-0-0'),
                array('user_id' => 2, 'body' => '1-0-0'),
                array('user_id' => 3, 'body' => '2-0-0'),
                array('user_id' => 4, 'body' => '1-1-0'),
                array('user_id' => 5, 'body' => '1-0-1'),
            ),
            $event->User->sentEmails
        );
    }

    public function testPublishFilterIsStillEvaluatedPerRecipient()
    {
        $event = $this->createEventModel();
        $event->User->usersWithAccess = array(
            $this->user(1, 1, 0),
            $this->user(2, 1, 0),
        );
        $event->User->UserSetting->rejectedUserIds = array(2);

        $event->sendAlertEmail(1, $this->senderUser());

        $this->assertSame(array('1-0-0'), $event->fetchedContexts);
        $this->assertSame(
            array(array('user_id' => 1, 'body' => '1-0-0')),
            $event->User->sentEmails
        );
    }

    /**
     * @return EventAlertEmailTestableEvent
     */
    private function createEventModel()
    {
        ClassRegistry::$instances['NotificationLog'] = new EventAlertEmailNotificationLog();
        $event = new EventAlertEmailTestableEvent();
        $event->User = new EventAlertEmailUser();
        $event->event = array(
            'Event' => array(
                'id' => 1,
                'org_id' => 1,
                'orgc_id' => 1,
                'distribution' => 3,
                'sharing_group_id' => 0,
            ),
        );
        return $event;
    }

    private function user($id, $orgId, $siteAdmin, $audit = 0)
    {
        return array(
            'id' => $id,
            'email' => 'user' . $id . '@test.local',
            'org_id' => $orgId,
            'Role' => array('perm_site_admin' => $siteAdmin, 'perm_audit' => $audit),
            'Organisation' => array('id' => $orgId, 'name' => 'Org ' . $orgId),
        );
    }

    private function senderUser()
    {
        return array(
            'id' => 99,
            'email' => 'sender@test.local',
            'org_id' => 1,
            'Role' => array('perm_site_admin' => 1, 'perm_audit' => 0),
        );
    }
}
