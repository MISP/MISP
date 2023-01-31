<?php
namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\ORM\Table;
use Cake\Validation\Validator;
use Cake\Datasource\EntityInterface;
use Cake\Event\Event;
use Cake\Event\EventInterface;
use Cake\Auth\DefaultPasswordHasher;
use Cake\Utility\Security;
use Cake\Core\Configure;
use Cake\Routing\Router;
use Cake\Http\Exception\MethodNotAllowedException;
use ArrayObject;

/**
 * @property Event $Event
 * @property User $User
 * @property Organisation $Organisation
 */
class AuditLogsTable extends AppTable
{
    const BROTLI_HEADER = "\xce\xb2\xcf\x81";
    const BROTLI_MIN_LENGTH = 200;

    const REQUEST_TYPE_DEFAULT = 0,
        REQUEST_TYPE_API = 1,
        REQUEST_TYPE_CLI = 2;

    /** @var array|null */
    private $user = null;

    /** @var bool */
    private $compressionEnabled;

    /**
     * Null when not defined, false when not enabled
     * @var Syslog|null|false
     */
    private $syslog;

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('Timestamp');
        $this->belongsTo('Users');
        $this->compressionEnabled = Configure::read('Cerebrate.log_new_audit_compress') && function_exists('brotli_compress');
    }

    public function beforeMarshal(EventInterface $event, ArrayObject $data, ArrayObject $options)
    {
        if (!isset($data['request_ip'])) {
            $ipHeader = 'REMOTE_ADDR';
            if (isset($_SERVER[$ipHeader])) {
                $data['request_ip'] = $_SERVER[$ipHeader];
            } else {
                $data['request_ip'] = '127.0.0.1';
            }
        }
        $defaults = [
            'user_id' => 0,
            'org_id' => 0,
            'request_type' => self::REQUEST_TYPE_CLI,
            'authkey_id' => 0
        ];
        foreach (array_keys($defaults) as $field) {
            if (!isset($data[$field])) {
                if (!isset($userInfo)) {
                    $userInfo = $this->userInfo();
                }
                if (!empty($userInfo[$field])) {
                    $data[$field] = $userInfo[$field];
                } else {
                    $data[$field] = 0;
                }
            }
        }

        if (!isset($data['request_id'] ) && isset($_SERVER['HTTP_X_REQUEST_ID'])) {
            $data['request_id'] = $_SERVER['HTTP_X_REQUEST_ID'];
        }

        // Truncate request_id
        if (isset($data['request_id']) && strlen($data['request_id']) > 255) {
            $data['request_id'] = substr($data['request_id'], 0, 255);
        }

        // Truncate model title
        if (isset($data['model_title']) && mb_strlen($data['model_title']) > 255) {
            $data['model_title'] = mb_substr($data['model_title'], 0, 252) . '...';
        }

        if (isset($data['changed'])) {
            $changed = json_encode($data['changed'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if ($this->compressionEnabled && strlen($changed) >= self::BROTLI_MIN_LENGTH) {
                $changed = self::BROTLI_HEADER . brotli_compress($changed, 4, BROTLI_TEXT);
            }
            $data['changed'] = $changed;
        }
        foreach ($defaults as $field => $default_value) {
            if (!isset($data[$field])) {
                $data[$field] = $default_value;
            }
        }
    }

    public function afterMarshal(
        EventInterface $event,
        EntityInterface $entity,
        ArrayObject $data,
        ArrayObject $options
    ) {
        if ($entity->request_type === null) {
            $entity->request_type = self::REQUEST_TYPE_CLI;
        }
    }

    public function beforeSave(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        $entity->request_ip = inet_pton($entity->request_ip);
        $this->logData($entity);
        return true;
    }

    /**
     * @param array $data
     * @return bool
     */
    private function logData(EntityInterface $entity)
    {
        if (Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_audit_notifications_enable')) {
            $pubSubTool = $this->getPubSubTool();
            $pubSubTool->publish($data, 'audit', 'log');
        }

        //$this->publishKafkaNotification('audit', $data, 'log');

        if (Configure::read('Plugin.ElasticSearch_logging_enable')) {
            // send off our logs to distributed /dev/null
            $logIndex = Configure::read("Plugin.ElasticSearch_log_index");
            $elasticSearchClient = $this->getElasticSearchTool();
            $elasticSearchClient->pushDocument($logIndex, "log", $data);
        }

        // write to syslogd as well if enabled
        if ($this->syslog === null) {
            if (Configure::read('Security.syslog')) {
                $options = [];
                $syslogToStdErr = Configure::read('Security.syslog_to_stderr');
                if ($syslogToStdErr !== null) {
                    $options['to_stderr'] = $syslogToStdErr;
                }
                $syslogIdent = Configure::read('Security.syslog_ident');
                if ($syslogIdent) {
                    $options['ident'] = $syslogIdent;
                }
                $this->syslog = new SysLog($options);
            } else {
                $this->syslog = false;
            }
        }
        if ($this->syslog) {
            $entry = $data['request_action'];
            $title = $entity->generateUserFriendlyTitle();
            if ($title) {
                $entry .= " -- $title";
            }
            $this->syslog->write('info', $entry);
        }
        return true;
    }

    /**
     * @return array
     */
    public function userInfo()
    {
        if ($this->user !== null) {
            return $this->user;
        }

        $this->user = ['id' => 0, /*'org_id' => 0, */'authkey_id' => 0, 'request_type' => self::REQUEST_TYPE_DEFAULT, 'name' => ''];

        $isShell = (php_sapi_name() === 'cli');
        if ($isShell) {
            // do not start session for shell commands and fetch user info from configuration
            $this->user['request_type'] = self::REQUEST_TYPE_CLI;
            $currentUserId = Configure::read('CurrentUserId');
            if (!empty($currentUserId)) {
                $this->user['id'] = $currentUserId;
                $userFromDb = $this->Users->find()->where(['id' => $currentUserId])->first();
                $this->user['name'] = $userFromDb['name'];
                $this->user['org_id'] = $userFromDb['org_id'];
            }
        } else {
            $authUser = Router::getRequest()->getSession()->read('authUser');
            if (!empty($authUser)) {
                $this->user['id'] = $authUser['id'];
                $this->user['user_id'] = $authUser['id'];
                $this->user['name'] = $authUser['name'];
                //$this->user['org_id'] = $authUser['org_id'];
                if (isset($authUser['logged_by_authkey']) && $authUser['logged_by_authkey']) {
                    $this->user['request_type'] = self::REQUEST_TYPE_API;
                }
                if (isset($authUser['authkey_id'])) {
                    $this->user['authkey_id'] = $authUser['authkey_id'];
                }
            }
        }
        return $this->user;
    }

    public function insert(array $data)
    {
        $logEntity = $this->newEntity($data);
        if ($logEntity->getErrors()) {
            throw new Exception($logEntity->getErrors());
        } else {
            $this->save($logEntity);
        }
    }

    /**
     * @param string|int $org
     * @return array
     */
    public function returnDates($org = 'all')
    {
        $conditions = [];
        if ($org !== 'all') {
            $org = $this->Organisation->fetchOrg($org);
            if (empty($org)) {
                throw new NotFoundException('Invalid organisation.');
            }
            $conditions['org_id'] = $org['id'];
        }

        $dataSource = ConnectionManager::getDataSource('default')->config['datasource'];
        if ($dataSource === 'Database/Mysql' || $dataSource === 'Database/MysqlObserver') {
            $validDates = $this->find('all', [
                'recursive' => -1,
                'fields' => ['DISTINCT UNIX_TIMESTAMP(DATE(created)) AS Date', 'count(id) AS count'],
                'conditions' => $conditions,
                'group' => ['Date'],
                'order' => ['Date'],
            ]);
        } elseif ($dataSource === 'Database/Postgres') {
            if (!empty($conditions['org_id'])) {
                $condOrg = sprintf('WHERE org_id = %s', intval($conditions['org_id']));
            } else {
                $condOrg = '';
            }
            $sql = 'SELECT DISTINCT EXTRACT(EPOCH FROM CAST(created AS DATE)) AS "Date", COUNT(id) AS count
                    FROM audit_logs
                    ' . $condOrg . '
                    GROUP BY "Date" ORDER BY "Date"';
            $validDates = $this->query($sql);
        }
        $data = [];
        foreach ($validDates as $date) {
            $data[(int)$date[0]['Date']] = (int)$date[0]['count'];
        }
        return $data;
    }
}
