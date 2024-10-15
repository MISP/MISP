<?php
App::uses('AppModel', 'Model');

/**
 * @property Event $Event
 * @property User $User
 * @property Organisation $Organisation
 */
class AuditLog extends AppModel
{
    const BROTLI_HEADER = "\xce\xb2\xcf\x81";
    const COMPRESS_MIN_LENGTH = 256;
    const CHANGE_MAX_SIZE = 64 * 1024; // MySQL type blob

    const ACTION_ADD = 'add',
        ACTION_EDIT = 'edit',
        ACTION_SOFT_DELETE = 'soft_delete',
        ACTION_DELETE = 'delete',
        ACTION_UNDELETE = 'undelete',
        ACTION_TAG = 'tag',
        ACTION_TAG_LOCAL = 'tag_local',
        ACTION_REMOVE_TAG = 'remove_tag',
        ACTION_REMOVE_TAG_LOCAL = 'remove_local_tag',
        ACTION_GALAXY = 'galaxy',
        ACTION_GALAXY_LOCAL = 'galaxy_local',
        ACTION_REMOVE_GALAXY = 'remove_galaxy',
        ACTION_REMOVE_GALAXY_LOCAL = 'remove_local_galaxy',
        ACTION_PUBLISH = 'publish',
        ACTION_PUBLISH_SIGHTINGS = 'publish_sightings';

    const REQUEST_TYPE_DEFAULT = 0,
        REQUEST_TYPE_API = 1,
        REQUEST_TYPE_CLI = 2;

    public $actsAs = [
        'Containable',
        'LightPaginator'
    ];

    /** @var array|null */
    private $user = null;

    /** @var bool */
    private $compressionEnabled;

    /** @var bool */
    private $pubToZmq;

    /** @var bool */
    private $logClientIp;

    /**
     * Null when not defined, false when not enabled
     * @var Syslog|null|false
     */
    private $syslog;

    public $compressionStats = [
        'compressed' => 0,
        'bytes_total' => 0,
        'bytes_compressed' => 0,
        'bytes_uncompressed' => 0,
    ];

    public $belongsTo = [
        'User' => [
            'className' => 'User',
            'foreignKey' => 'user_id',
        ],
        'Event' => [
            'className' => 'Event',
            'foreignKey' => 'event_id',
        ],
        'Organisation' => [
            'className' => 'Organisation',
            'foreignKey' => 'org_id',
        ],
    ];

    public function __construct($id = false, $table = null, $ds = null)
    {
        parent::__construct($id, $table, $ds);
        $this->compressionEnabled = Configure::read('MISP.log_new_audit_compress') &&
            function_exists('brotli_compress');
        $this->pubToZmq = $this->pubToZmq('audit');
        $this->logClientIp = Configure::read('MISP.log_client_ip');
    }

    public function afterFind($results, $primary = false)
    {
        foreach ($results as &$result) {
            if (isset($result['AuditLog']['ip'])) {
                $result['AuditLog']['ip'] = inet_ntop($result['AuditLog']['ip']);
            }
            if (isset($result['AuditLog']['change']) && $result['AuditLog']['change']) {
                $result['AuditLog']['change'] = $this->decodeChange($result['AuditLog']['change']);
            }
            if (isset($result['AuditLog']['action']) && isset($result['AuditLog']['model']) && isset($result['AuditLog']['model_id'])) {
                $result['AuditLog']['title'] = $this->generateUserFriendlyTitle($result['AuditLog']);
            }
        }
        return $results;
    }

    /**
     * @param array $auditLog
     * @return string
     */
    private function generateUserFriendlyTitle(array $auditLog)
    {
        if (in_array($auditLog['action'], [self::ACTION_TAG, self::ACTION_TAG_LOCAL, self::ACTION_REMOVE_TAG, self::ACTION_REMOVE_TAG_LOCAL], true)) {
            $attached = ($auditLog['action'] === self::ACTION_TAG || $auditLog['action'] === self::ACTION_TAG_LOCAL);
            $local = ($auditLog['action'] === self::ACTION_TAG_LOCAL || $auditLog['action'] === self::ACTION_REMOVE_TAG_LOCAL) ? __('local') : __('global');
            if ($attached) {
                return __('Attached %s tag "%s" to %s #%s', $local, $auditLog['model_title'], strtolower($auditLog['model']), $auditLog['model_id']);
            } else {
                return __('Detached %s tag "%s" from %s #%s', $local, $auditLog['model_title'], strtolower($auditLog['model']), $auditLog['model_id']);
            }
        }

        if (in_array($auditLog['action'], [self::ACTION_GALAXY, self::ACTION_GALAXY_LOCAL, self::ACTION_REMOVE_GALAXY, self::ACTION_REMOVE_GALAXY_LOCAL], true)) {
            $attached = ($auditLog['action'] === self::ACTION_GALAXY || $auditLog['action'] === self::ACTION_GALAXY_LOCAL);
            $local = ($auditLog['action'] === self::ACTION_GALAXY_LOCAL || $auditLog['action'] === self::ACTION_REMOVE_GALAXY_LOCAL) ? __('local') : __('global');
            if ($attached) {
                return __('Attached %s galaxy cluster "%s" to %s #%s', $local, $auditLog['model_title'], strtolower($auditLog['model']), $auditLog['model_id']);
            } else {
                return __('Detached %s galaxy cluster "%s" from %s #%s', $local, $auditLog['model_title'], strtolower($auditLog['model']), $auditLog['model_id']);
            }
        }

        if (in_array($auditLog['model'], ['Attribute', 'Object', 'ShadowAttribute'], true)) {
            $modelName = $auditLog['model'] === 'ShadowAttribute' ? 'Proposal' : $auditLog['model'];
            $title = __('%s from Event #%s', $modelName, $auditLog['event_id']);
        }

        if (isset($auditLog['model_title']) && $auditLog['model_title']) {
            if (isset($title)) {
                $title .= ": {$auditLog['model_title']}";
                return $title;
            } else {
                return $auditLog['model_title'];
            }
        }
        return '';
    }

    /**
     * @param mixed $change
     * @return string
     * @throws JsonException
     */
    private function encodeChange($change)
    {
        $change = JsonTool::encode($change);
        if ($this->compressionEnabled && strlen($change) >= self::COMPRESS_MIN_LENGTH) {
            return self::BROTLI_HEADER . brotli_compress($change, 4, BROTLI_TEXT);
        }
        return $change;
    }

    /**
     * @param string $change
     * @return array|string
     * @throws JsonException
     */
    private function decodeChange($change)
    {
        $len = strlen($change);
        $this->compressionStats['bytes_total'] += $len;
        if (str_starts_with($change, self::BROTLI_HEADER)) {
            $this->compressionStats['compressed']++;
            if (function_exists('brotli_uncompress')) {
                $this->compressionStats['bytes_compressed'] += $len;
                $change = brotli_uncompress(substr($change, 4));
                $this->compressionStats['bytes_uncompressed'] += strlen($change);
                if ($change === false) {
                    return 'Compressed';
                }
            } else {
                return 'Compressed';
            }
        }
        return JsonTool::decode($change);
    }

    public function beforeValidate($options = array())
    {
        if (isset($this->data['AuditLog']['change']) && !is_array($this->data['AuditLog']['change'])) {
            $this->invalidate('change', 'Change field must be array');
        }
    }

    public function beforeSave($options = array())
    {
        $auditLog = &$this->data['AuditLog'];
        if (!isset($auditLog['ip']) && $this->logClientIp) {
            $auditLog['ip'] = $this->_remoteIp();
        }

        if (!isset($auditLog['user_id'])) {
            $auditLog['user_id'] = $this->userInfo()['id'];
        }

        if (!isset($auditLog['org_id'])) {
            $auditLog['org_id'] = $this->userInfo()['org_id'];
        }

        if (!isset($auditLog['request_type'])) {
            $auditLog['request_type'] = $this->userInfo()['request_type'];
        }

        if (!isset($auditLog['authkey_id'])) {
            $auditLog['authkey_id'] = $this->userInfo()['authkey_id'];
        }

        if (!isset($auditLog['request_id'] ) && isset($_SERVER['HTTP_X_REQUEST_ID'])) {
            $auditLog['request_id'] = $_SERVER['HTTP_X_REQUEST_ID'];
        }

        // Truncate request_id
        if (isset($auditLog['request_id']) && strlen($auditLog['request_id']) > 255) {
            $auditLog['request_id'] = substr($auditLog['request_id'], 0, 255);
        }

        // Truncate model title
        if (isset($auditLog['model_title']) && mb_strlen($auditLog['model_title']) > 255) {
            $auditLog['model_title'] = mb_substr($auditLog['model_title'], 0, 252) . '...';
        }

        $this->logData($this->data);

        if (isset($auditLog['ip'])) {
            $auditLog['ip'] = inet_pton($auditLog['ip']); // convert to binary form to save into database
        }

        if (isset($auditLog['change'])) {
            $auditLog['change'] = $this->encodeChange($auditLog['change']);
            if (strlen($auditLog['change']) > self::CHANGE_MAX_SIZE) {
                // Change is too big to save in database, skipping
                $auditLog['change'] = null;
            }
        }
    }

    /**
     * @param array $data
     * @return bool
     */
    private function logData(array $data)
    {
        if ($this->pubToZmq) {
            $pubSubTool = $this->getPubSubTool();
            $pubSubTool->publish($data, 'audit', 'log');
        }

        $this->publishKafkaNotification('audit', $data, 'log');

        // In future add support for sending logs to elastic

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
            $entry = $data['AuditLog']['action'];
            $title = $this->generateUserFriendlyTitle($data['AuditLog']);
            if ($title) {
                $entry .= " -- $title";
            }
            $this->syslog->write(LOG_INFO, $entry);
        }
        return true;
    }

    /**
     * @return array
     */
    private function userInfo()
    {
        if ($this->user !== null) {
            return $this->user;
        }

        $this->user = ['id' => 0, 'org_id' => 0, 'authkey_id' => 0, 'request_type' => self::REQUEST_TYPE_DEFAULT];

        $isShell = defined('CAKEPHP_SHELL') && CAKEPHP_SHELL;
        if ($isShell) {
            // do not start session for shell commands and fetch user info from configuration
            $this->user['request_type'] = self::REQUEST_TYPE_CLI;
            $currentUserId = Configure::read('CurrentUserId');
            if (!empty($currentUserId)) {
                $this->user['id'] = $currentUserId;
                $userFromDb = $this->User->find('first', [
                    'conditions' => ['User.id' => $currentUserId],
                    'fields' => ['User.org_id'],
                ]);
                $this->user['org_id'] = $userFromDb['User']['org_id'];
            }
        } else {
            App::uses('AuthComponent', 'Controller/Component');
            $authUser = AuthComponent::user();
            if (!empty($authUser)) {
                $this->user['id'] = $authUser['id'];
                $this->user['org_id'] = $authUser['org_id'];
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

    /**
     * @throws Exception
     */
    public function insert(array $data)
    {
        try {
            $this->create();
        } catch (Exception $e) {
            return; // Table is missing when updating, so this is intentional
        }
        if ($this->save(['AuditLog' => $data], ['atomic' => false]) === false) {
            throw new Exception($this->validationErrors);
        }
    }

    /**
     * @throws JsonException
     * @throws Exception
     */
    public function recompress()
    {
        $changes = $this->find('all', [
            'fields' => ['AuditLog.id', 'AuditLog.change'],
            'recursive' => -1,
            'conditions' => ['OR' => [
                ['length(AuditLog.change) >=' => self::COMPRESS_MIN_LENGTH],
                ['AuditLog.change LIKE' => self::BROTLI_HEADER . '%'],
            ]],
        ]);

        $options = [
            'validate' => false,
            'callbacks' => false,
            'fieldList' => ['change'],
        ];

        foreach (array_chunk($changes, 100) as $chunk) {
            $toSave = [];
            foreach ($chunk as $change) {
                $change['AuditLog']['change'] = $this->encodeChange($change['AuditLog']['change']);
                $toSave[] = $change;
            }
            $this->saveMany($toSave, $options);
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

        if ($this->isMysql()) {
            $validDates = $this->find('all', [
                'recursive' => -1,
                'fields' => ['DISTINCT UNIX_TIMESTAMP(DATE(created)) AS Date', 'count(id) AS count'],
                'conditions' => $conditions,
                'group' => ['Date'],
                'order' => ['Date'],
                'callbacks' => false,
            ]);
        } else {
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
