<?php
App::uses('AppModel', 'Model');

class Log extends AppModel
{
    const WARNING_ACTIONS = [
        'warning',
        'change_pw',
        'login_fail',
        'version_warning',
        'auth_fail'
    ];

    const ERROR_ACTIONS = [
        'error'
    ];

    const AUTH_ACTIONS = [
        'auth',
        'auth_fail',
        'auth_alert',
        'change_pw',
        'login',
        'login_fail',
        'logout',
        'password_reset',
        'forgot',
    ];

    // Every action the application log can hold. The index's Action
    // dropdown is built from this, so a value missing here is a value
    // nobody can filter on.
    const ACTIONS = [ // ensure that the length of the rules is < 20 in length
        'accept',
        'accept_delegation',
        'acceptRegistrations',
        'add',
        'admin_email',
        'attachTags',
        'attachTagToObject',
        'auth',
        'auth_fail',
        'auth_alert',
        'blocklisted',
        'captureRelations',
        'change_pw',
        'delete',
        'disable',
        'discard',
        'discardRegistrations',
        'edit',
        'email',
        'enable',
        'enrichment',
        'error',
        'execute_blueprint',
        'execute_workflow',
        'exec_module',
        'export',
        'fetchEvent',
        'file_upload',
        'forgot',
        'galaxy',
        'include_formula',
        'load_module',
        'login',
        'login_fail',
        'logout',
        'merge',
        'password_reset',
        'pruneUpdateLogs',
        'publish',
        'publish_sightings',
        'publish alert',
        'pull',
        'purge_events',
        'push',
        'registration',
        'registration_error',
        'remove_dead_workers',
        'removeTagFromObject',
        'request',
        'request_delegation',
        'reset_auth_key',
        'send_mail',
        'security',
        'serverSettingsEdit',
        'tag',
        'undelete',
        'update',
        'update_database',
        'update_db_worker',
        'updateCryptoKeys',
        'upgrade_24',
        'upload_sample',
        'validateSig',
        'version_warning',
        'warning',
        'wipe_default'
    ];

    public $validate = array(
        'action' => array(
            'rule' => array('inList', self::ACTIONS),
            'message' => 'Options : ...'
        )
    );

    public $truncatedColumns = ['title', 'change', 'description'];

    public $searchModelList = [
        'Attribute',
        'Allowedlist',
        'AuthKey',
        'Event',
        'EventBlocklist',
        'EventTag',
        'Feed',
        'DecayingModel',
        'EventGraph',
        'EventReport',
        'MispObject',
        'Organisation',
        'Post',
        'Regexp',
        'Role',
        'Server',
        'ShadowAttribute',
        'SharingGroup',
        'Tag',
        'Task',
        'Taxonomy',
        'Template',
        'Thread',
        'User',
        'Galaxy',
        'GalaxyCluster',
        'GalaxyClusterRelation',
        'Workflow',
    ];

    public $actionDefinitions = array(
        'login' => array('desc' => 'Login action', 'formdesc' => "Login action"),
        'logout' => array('desc' => 'Logout action', 'formdesc' => "Logout action"),
        'add' => array('desc' => 'Add action', 'formdesc' => "Add action"),
        'edit' => array('desc' => 'Edit action', 'formdesc' => "Edit action"),
        'change_pw' => array('desc' => 'Change_pw action', 'formdesc' => "Change_pw action"),
        'delete' => array('desc' => 'Delete action', 'formdesc' => "Delete action"),
        'publish' => array('desc' => "Publish action", 'formdesc' => "Publish action")
    );

    public $logMeta = array(
        'email' => array('values' => array('email'), 'name' => 'Emails'),
        'auth_issues' => array('values' => array('login_fail', 'auth_fail', 'auth_alert'), 'name' => 'Authentication issues')
    );

    public $logMetaAdmin = array(
        'update' => array('values' => array('update_database'), 'name' => 'MISP Update results'),
        'settings' => array('values' => array('serverSettingsEdit', 'remove_dead_workers'), 'name' => 'Setting changes'),
        'errors' => array('values' => array('warning', 'error', 'version_warning'), 'name' => 'Warnings and errors'),
        'email' => array('values' => array('admin_email'))
    );

    public $actsAs = ['LightPaginator'];

    private $elasticSearchClient;

    /**
     * Null when not defined, false when not enabled
     * @var Syslog|null|false
     */
    private $syslog;

    public function beforeValidate($options = [])
    {
        if (!empty($this->data['Log']['change'])) {
            if (is_array($this->data['Log']['change'])) {
                $output = [];
                foreach ($this->data['Log']['change'] as $field => $values) {
                    $sanitiseFields = ['password', 'api_key', 'authkey', 'headers', 'api_token', 'token', 'key'];
                    $isSecret = in_array($field, $sanitiseFields) || ($field === 'authkey' && Configure::read('Security.do_not_log_authkeys'));
                    if ($isSecret) {
                        $oldValue = $newValue = "*****";
                    } else {
                        list($oldValue, $newValue) = $values;
                    }
                    $output[] = "$field ($oldValue) => ($newValue)";
                }
                $this->data['Log']['change'] = implode(", ", $output);
            }
    
        }
        return true;
    }

    public function beforeSave($options = array())
    {
        if (!empty(Configure::read('MISP.log_skip_db_logs_completely'))) {
            return false;
        }
        if (Configure::read('MISP.log_client_ip')) {
            $this->data['Log']['ip'] = $this->_remoteIp();
        }
        $this->data['Log']['request_is_rest'] = Configure::read('CurrentRequestIsRest');
        $setEmpty = array('title' => '', 'model' => '', 'model_id' => 0, 'action' => '', 'user_id' => 0, 'change' => '', 'email' => '', 'org' => '', 'description' => '', 'ip' => '');
        foreach ($setEmpty as $field => $empty) {
            if (empty($this->data['Log'][$field])) {
                $this->data['Log'][$field] = $empty;
            }
        }
        if (!isset($this->data['Log']['created'])) {
            $this->data['Log']['created'] = date('Y-m-d H:i:s');
        }
        if (empty($this->data['Log']['org'])) {
            $this->data['Log']['org'] = 'SYSTEM';
        }
        // Sanitize before the length check, so that the replaced bytes count towards truncation.
        $utf8mb3 = $this->isUtf8mb3();
        foreach ($this->truncatedColumns as $tf) {
            if (!empty($this->data['Log'][$tf]) && is_string($this->data['Log'][$tf])) {
                $this->data['Log'][$tf] = $utf8mb3
                    ? JsonTool::sanitizeForUtf8mb3($this->data['Log'][$tf])
                    : JsonTool::escapeNonUnicode($this->data['Log'][$tf]);
            }
            if (strlen($this->data['Log'][$tf]) >= 65535) {
                $this->data['Log'][$tf] = mb_strcut($this->data['Log'][$tf], 0, 65532, 'UTF-8') . '...';
            }
        }
        $this->logData($this->data);
        if ($this->data['Log']['action'] === 'request' && !empty(Configure::read('MISP.log_paranoid_skip_db'))) {
            return false;
        }
        return true;
    }

    /**
     * Whether `logs` still has its pre-3.0 utf8mb3 layout, which refuses
     * 4-byte characters. `Console/cake LogTables upgrade` moves it on; fresh
     * installs start at utf8mb4.
     *
     * @return bool
     */
    private function isUtf8mb3()
    {
        $title = $this->schema('title');
        return isset($title['charset']) && $title['charset'] !== 'utf8mb4';
    }

    public function afterSave($created, $options = array())
    {
        // run workflow if needed, but skip workflow for certain types, to prevent loops
        if (!in_array($this->data['Log']['model'], ['Log', 'Workflow'])) {
            $trigger_id = 'log-after-save';
            $workflowErrors = [];
            $this->executeTrigger($trigger_id, $this->data, $workflowErrors);
        }
        return true;
    }

    public function returnDates($org = 'all')
    {
        $conditions = array();
        $this->Organisation = ClassRegistry::init('Organisation');
        if ($org !== 'all') {
            $org = $this->Organisation->fetchOrg($org);
            if (empty($org)) {
                throw new MethodNotAllowedException('Invalid organisation.');
            }
            $conditions['org'] = $org['name'];
        }
        $conditions['AND']['NOT'] = array('action' => array('login', 'logout', 'changepw'));
        // One query for both engines. The PostgreSQL half used to drop out of
        // the ORM and be written by hand - the comment it carried said why:
        // the ORM escapes the DATE keyword inside a CAST expression. The
        // dialect's cast spelling has no DATE keyword in it.
        $dialect = $this->getSqlDialect();
        $day = $dialect->unixTimestamp($dialect->dateOf('created'));
        // Lower-case alias on purpose: an unquoted `AS Date` comes back as
        // `Date` from MySQL and as `date` from PostgreSQL, which folds unquoted
        // identifiers. Reading the row by a key only one engine produces would
        // have collapsed every bucket into one.
        $validDates = $this->find('all', array(
                'fields' => array('DISTINCT ' . $day . ' AS date', 'count(id) AS count'),
                'conditions' => $conditions,
                'group' => array('date'),
                'order' => array('date')
        ));
        $data = array();
        foreach ($validDates as $date) {
            $data[$date[0]['date']] = intval($date[0]['count']);
        }
        return $data;
    }

    /**
     * @param string|array $user
     * @param string $action
     * @param string $model
     * @param int $modelId
     * @param string $title
     * @param string|array $change
     * @return array|null
     * @throws Exception
     * @throws InvalidArgumentException
     */
    public function createLogEntry($user, $action, $model, $modelId = 0, $title = '', $change = '')
    {
        if (in_array($action, ['tag', 'galaxy', 'publish', 'publish_sightings', 'enable', 'edit'], true) && Configure::read('MISP.log_new_audit')) {
            return; // Do not store tag changes when new audit is enabled
        }
        if ($user === 'SYSTEM') {
            $user = ['Organisation' => ['name' => 'SYSTEM'], 'email' => 'SYSTEM', 'id' => 0];
        } else if (!is_array($user)) {
            throw new InvalidArgumentException("User must be array or 'SYSTEM' string.");
        }

        if (is_array($change)) {
            $output = [];
            foreach ($change as $field => $values) {
                $isSecret = str_contains($field, 'password') || $field === 'api_key' || $field === 'headers' || ($field === 'authkey' && Configure::read('Security.do_not_log_authkeys'));
                if ($isSecret) {
                    $oldValue = $newValue = "*****";
                } else {
                    list($oldValue, $newValue) = $values;
                }
                $output[] = "$field ($oldValue) => ($newValue)";
            }
            $change = implode(", ", $output);
        }

        // If Sentry is installed, send log breadcrumb to Sentry
        if (function_exists('\Sentry\addBreadcrumb')) {
            \Sentry\addBreadcrumb('log', $title, [], Sentry\Breadcrumb::LEVEL_INFO);
        }

        $this->create();
        $result = $this->save(['Log' => [
            'org' => $user['Organisation']['name'],
            'email' => $user['email'],
            'user_id' => $user['id'],
            'action' => $action,
            'title' => $title,
            'change' => $change,
            'model' => $model,
            'model_id' => $modelId,
        ]]);

        if (!$result) {
            if ($action === 'request' && !empty(Configure::read('MISP.log_paranoid_skip_db'))) {
                return null;
            }
            if (!empty(Configure::read('MISP.log_skip_db_logs_completely'))) {
                return null;
            }

            throw new Exception("Cannot save log because of validation errors: " . json_encode($this->validationErrors));
        }

        return $result;
    }

    /**
     * @param array|string $user
     * @param string $action
     * @param string $model
     * @param string $title
     * @param array $validationErrors
     * @param array $fullObject
     * @throws Exception
     */
    public function validationError($user, $action, $model, $title, array $validationErrors, array $fullObject)
    {
        $this->log($title, LOG_WARNING);
        $change = 'Validation errors: ' . JsonTool::encode($validationErrors) . ' Full ' . $model  . ': ' . JsonTool::encode($fullObject);
        $this->createLogEntry($user, $action, $model, 0, $title, $change);
    }

    private function logData(array $data)
    {
        if ($this->pubToZmq('audit')) {
            $this->getPubSubTool()->publish($data, 'audit', 'log');
        }

        $this->publishKafkaNotification('audit', $data, 'log');

        if (Configure::read('Plugin.ElasticSearch_logging_enable')) {
            // send off our logs to distributed /dev/null
            $logIndex = Configure::read("Plugin.ElasticSearch_log_index");
            $elasticSearchClient = $this->getElasticSearchTool();
            $elasticSearchClient->pushDocument($logIndex, "log", $data);
        }

        // Do not save request action logs to syslog, because they contain no information
        if ($data['Log']['action'] === 'request') {
            return true;
        }

        // write to syslogd as well if enabled
        $this->sendToSyslog($data);
        $this->sendToEcs($data);

        return true;
    }

    private function sendToSyslog(array $data)
    {
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
                App::uses('SysLog', 'SysLog.Lib');
                $this->syslog = new SysLog($options);
            } else {
                $this->syslog = false;
            }
        }
        if ($this->syslog) {
            $action = LOG_INFO;
            if (isset($data['Log']['action'])) {
                if (in_array($data['Log']['action'], self::ERROR_ACTIONS, true)) {
                    $action = LOG_ERR;
                } else if (in_array($data['Log']['action'], self::WARNING_ACTIONS, true)) {
                    $action = LOG_WARNING;
                }
            }

            if (Configure::read('Security.syslog_json_format')) {
                if (isset($data['Log']['change']) && mb_strlen($data['Log']['change']) > 4096) {
                    $data['Log']['change'] = mb_strcut($data['Log']['change'], 0, 4096, 'UTF-8');
                    $data['Log']['_truncated'] = true;
                }
                $entry = JsonTool::encode($data['Log']);
            } else {
                $entry = sprintf(
                    '%s -- %s -- %s',
                    $data['Log']['action'],
                    empty($data['Log']['title']) ? '' : preg_replace('/\s+/', " ", $data['Log']['title']),
                    empty($data['Log']['description']) ? 
                        (empty($data['Log']['change']) ? '' : preg_replace('/\s+/', " ", $data['Log']['change'])) :
                        preg_replace('/\s+/', " ", $data['Log']['description'])
                );
            }
            $this->syslog->write($action, $entry);
        }
    }

    /**
     * @param array $data
     * @return void
     * @throws JsonException
     */
    private function sendToEcs(array $data)
    {
        if (!Configure::read('Security.ecs_log')) {
            return;
        }

        $log = $data['Log'];

        $action = $log['action'];
        if ($action === 'email') {
            return; // do not log email actions as it is logged with more details by `writeEmailLog` function
        }

        if (in_array($action, self::ERROR_ACTIONS, true)) {
            $type = 'error';
        } else if (in_array($action, self::WARNING_ACTIONS, true)) {
            $type = 'warning';
        } else {
            $type = 'info';
        }

        $message = $action;
        if (!empty($log['title'])) {
            $message .= " -- {$log['title']}";
        }
        if (!empty($log['description'])) {
            $message .= " -- {$log['description']}";
        } else if (!empty($log['change'])) {
            $message .= " -- " . (is_string($log['change']) ? $log['change'] : JsonTool::encode($log['change']));
        }

        EcsLog::writeApplicationLog($type, $action, $message);
    }

    public function filterSiteAdminSensitiveLogs($list)
    {
        $this->User = ClassRegistry::init('User');
        $site_admin_roles = $this->User->Role->find('list', array(
            'recursive' => -1,
            'conditions' => array('Role.perm_site_admin' => 1),
            'fields' => array('Role.id', 'Role.id')
        ));
        $site_admins = $this->User->find('list', array(
            'recursive' => -1,
            'conditions' => array(
                'User.role_id' => array_values($site_admin_roles)
            ),
            'fields' => array('User.id', 'User.id')
        ));
        foreach ($list as $k => $v) {
            if (
                $v['Log']['model'] === 'User' &&
                in_array($v['Log']['model_id'], array_values($site_admins)) &&
                in_array($v['Log']['action'], array('add', 'edit', 'reset_auth_key'))
            ) {
                $list[$k]['Log']['change'] = __('Redacted');
            }
        }
        return $list;
    }

    public function changeParser($change)
    {
        $change = explode(',', $change);
        $data = [];
        foreach ($change as $entry) {
            $entry = trim($entry);
            $fieldName = explode(' ', $entry)[0];
            $entry = substr($entry, strlen($fieldName));
            $entry = trim($entry);
            if (strpos($entry, ') => (')) {
                list($before, $after) = explode(') => (', $entry);
                $before = substr($before, 1);
                $after = substr($after, 0, -1);
                $data[$fieldName] = $after;
            }
        }
        return $data;
    }

    private function getElasticSearchTool()
    {
        if (!$this->elasticSearchClient) {
            App::uses('ElasticSearchClient', 'Tools');
            $client = new ElasticSearchClient();
            $client->initTool();
            $this->elasticSearchClient = $client;
        }
        return $this->elasticSearchClient;
    }

    /**
     * @param $data
     * @param $options
     * @return array|bool|mixed
     */
    public function saveOrFailSilently($data, $options = null)
    {
        try {
            return $this->save($data, $options);
        } catch (Exception $e) {
            $this->logException('Could not save log to database', $e);
            return false;
        }
    }
}
