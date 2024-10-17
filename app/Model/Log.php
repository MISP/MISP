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

    public $validate = array(
        'action' => array(
            'rule' => array(
                'inList',
                array( // ensure that the length of the rules is < 20 in length
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
                )
            ),
            'message' => 'Options : ...'
        )
    );

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

    public function beforeSave($options = array())
    {
        if (!empty(Configure::read('MISP.log_skip_db_logs_completely'))) {
            return false;
        }
        if (Configure::read('MISP.log_client_ip')) {
            $this->data['Log']['ip'] = $this->_remoteIp();
        }
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
        $truncate_fields = array('title', 'change', 'description');
        foreach ($truncate_fields as $tf) {
            if (strlen($this->data['Log'][$tf]) >= 65535) {
                $this->data['Log'][$tf] = substr($this->data['Log'][$tf], 0, 65532) . '...';
            }
        }
        $this->logData($this->data);
        if ($this->data['Log']['action'] === 'request' && !empty(Configure::read('MISP.log_paranoid_skip_db'))) {
            return false;
        }
        return true;
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
        if ($this->isMysql()) {
            $validDates = $this->find('all', array(
                    'fields' => array('DISTINCT UNIX_TIMESTAMP(DATE(created)) AS Date', 'count(id) AS count'),
                    'conditions' => $conditions,
                    'group' => array('Date'),
                    'order' => array('Date')
            ));
        } else {
            // manually generate the query for Postgres
            // cakephp ORM would escape "DATE" datatype in CAST expression
            $condnotinaction = "'" . implode("', '", $conditions['AND']['NOT']['action']) . "'";
            if (!empty($conditions['org'])) {
                $condOrg = sprintf('AND org = %s', $this->getDataSource()->value($conditions['org']));
            } else {
                $condOrg = '';
            }
            $sql = 'SELECT DISTINCT EXTRACT(EPOCH FROM CAST(created AS DATE)) AS "Date",
                                    COUNT(id) AS count
                    FROM logs
                    WHERE action NOT IN (' . $condnotinaction . ')
                    ' . $condOrg . '
                    GROUP BY "Date" ORDER BY "Date"';
            $validDates = $this->query($sql);
        }
        $data = array();
        foreach ($validDates as $date) {
            $data[$date[0]['Date']] = intval($date[0]['count']);
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
                $isSecret = strpos($field, 'password') !== false || ($field === 'authkey' && Configure::read('Security.do_not_log_authkeys'));
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

    // to combat a certain bug that causes the upgrade scripts to loop without being able to set the correct version
    // this function remedies a fixed upgrade bug instance by eliminating the massive number of erroneous upgrade log entries
    public function pruneUpdateLogs($jobId = false, $user)
    {
        $max = $this->find('first', array('fields' => array('MAX(id) AS lastid')));
        if (!empty($max)) {
            $max = $max[0]['lastid'];
        }
        if ($jobId) {
            $this->Job = ClassRegistry::init('Job');
            $this->Job->id = $jobId;
            if (!$this->Job->exists()) {
                $jobId = false;
            }
        }
        $iterations = ($max / 1000);
        for ($i = 0; $i < $iterations; $i++) {
            $this->deleteAll(array(
                'OR' => array(
                        'action' => 'update_database',
                        'AND' => array(
                            'action' => 'edit',
                            'model' => 'AdminSetting'
                        )
                ),
                'id >' => $i * 1000,
                'id <' => ($i+1) * 1000));
            if ($jobId) {
                $this->Job->saveField('progress', $i * 100 / $iterations);
            }
        }
        $this->create();
        $this->save(array(
                'org' => $user['Organisation']['name'],
                'email' =>$user['email'],
                'user_id' => $user['id'],
                'action' => 'pruneUpdateLogs',
                'title' => 'Pruning updates',
                'change' => 'Pruning completed in ' . $i . ' iteration(s).',
                'model' => 'Log',
                'model_id' => 0
        ));
    }

    public function pruneUpdateLogsRouter($user)
    {
        if (Configure::read('MISP.background_jobs')) {

            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob(
                $user,
                Job::WORKER_DEFAULT,
                'prune_update_logs',
                'All update entries',
                'Purging the heretic.'
            );

            return $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_ADMIN,
                [
                    'prune_update_logs',
                    $jobId,
                    $user['id']
                ],
                true,
                $jobId
            );
        } else {
            $result = $this->pruneUpdateLogs(false, $user);
            return $result;
        }
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

            $entry = sprintf(
                '%s -- %s -- %s',
                $data['Log']['action'],
                empty($data['Log']['title']) ? '' : $formatted_title = preg_replace('/\s+/', " ", $data['Log']['title']),
                empty($data['Log']['description']) ? 
                    (empty($data['Log']['change']) ? '' : preg_replace('/\s+/', " ", $data['Log']['change'])) :
                    preg_replace('/\s+/', " ", $data['Log']['description'])
            );
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

    public function findDeletedEvents($conditions)
    {
        $conditions['model'] = 'Event';
        $conditions['action'] = 'delete';
        $this->Event = ClassRegistry::init('Event');
        $deletions = $this->find('all', [
            'recursive' => -1,
            'conditions' => $conditions,
            'order' => ['Log.id']
        ]);
        $deleted_events = [];
        $users = [];
        $orgs = [];
        $deleted_event_ids = [];
        foreach ($deletions as $deletion_entry) {
            if (!empty($deleted_event_ids[$deletion_entry['Log']['model_id']])) {
                continue;
            } else {
                $deleted_event_ids[$deletion_entry['Log']['model_id']] = true;
            }
            $event = $this->Event->find('first', [
                'conditions' => ['Event.id' => $deletion_entry['Log']['model_id']],
                'recursive' => -1,
                'fields' => ['Event.id']
            ]);
            if (!empty($event)) {
                // event is already restored / not deleted
                continue;
            }
            $temp = [
                'event_id' => $deletion_entry['Log']['model_id'],
                'user_id' => $deletion_entry['Log']['user_id'],
                'created' => $deletion_entry['Log']['created']
            ];
            $event_creation_entry = $this->find('first', [
                'recursive' => -1,
                'conditions' => [
                    'model_id' => $temp['event_id'],
                    'model' => 'Event',
                    'action' => 'add'
                ]
            ]);
            $event = $this->changeParser($event_creation_entry['Log']['change']);
            $temp['event_info'] = $event['info'];
            $temp['event_org_id'] = $event['org_id'];
            $temp['event_orgc_id'] = $event['orgc_id'];
            $temp['event_user_id'] = $event['user_id'];
            $temp['event_info'] = $event['info'];
            $temp['event_created'] = $event_creation_entry['Log']['created'];
            foreach (['org', 'orgc'] as $scope) {
                if (empty($orgs[$temp['event_' . $scope . '_id']])) {
                    $orgs[$temp['event_' . $scope . '_id']] = array_values($this->Event->Orgc->find('list', [
                        'recursive' => -1,
                        'conditions' => array('id' => $temp['event_' . $scope . '_id']),
                        'fields' => array('id', 'name')
                    ]))[0];
                }
                $temp['event_' . $scope . '_name'] = $orgs[$temp['event_' . $scope . '_id']];
            }
            $users[$temp['user_id']] = array_values($this->Event->User->find('list', [
                'recursive' => -1,
                'conditions' => array('id' => $temp['user_id']),
                'fields' => array('id', 'email')
            ]))[0];
            $temp['user_name'] = $users[$temp['user_id']];
            $users[$temp['event_user_id']] = array_values($this->Event->User->find('list', [
                'recursive' => -1,
                'conditions' => array('id' => $temp['event_user_id']),
                'fields' => array('id', 'email')
            ]))[0];
            $temp['event_user_name'] = $users[$temp['event_user_id']];
            $deleted_events[] = $temp;
        }
        return $deleted_events;
    }

    public function recoverDeletedEvent($id, $mock = false)
    {
        if ($mock) {
            $this->mockRecovery = true;
            $this->mockLog = [];
        }
        $objectMap = [];
        $logEntries = [];
        $this->__recoverDeletedEventContainer($id, $objectMap, $logEntries);
        $this->__recoverDeletedObjects($id, $objectMap, $logEntries);
        $this->__recoverDeletedAttributes($id, $objectMap, $logEntries);
        $this->__recoverDeletedObjectReferences($id, $objectMap, $logEntries);
        $this->__recoverDeletedTagConnectors($id, $objectMap, $logEntries, 'Event');
        $this->__recoverDeletedTagConnectors($id, $objectMap, $logEntries, 'Attribute');
        $this->__recoverDeletedProposals($id, $objectMap, $logEntries);
        ksort($logEntries);
        foreach ($logEntries as $logEntry) {
            $this->{'__executeRecovery' . $logEntry['model']}($logEntry, $id);
        }
        return count($logEntries);
        // order: event -> object -> attribute -> object reference -> tag -> galaxy -> shadow_attribute -> sighting
    }

    private function __recoverDeletedEventContainer($id, &$objectMap, &$logEntries)
    {
        $logs = $this->find('all', [
            'recursive' => -1,
            'conditions' => [
                'model' => 'Event',
                'model_id' => $id,
                'action' => ['add', 'edit', 'publish', 'alert']
            ]
        ]);
        if (empty($logs)) {
            return;
        }
        foreach ($logs as $log) {
            $logEntries[$log['Log']['id']] = [
                'model_id' => $log['Log']['model_id'],
                'model' => $log['Log']['model'],
                'action' => $log['Log']['action'],
                'data' => array_merge(
                    $this->changeParser($log['Log']['change']),
                    [
                        'timestamp' => strtotime($log['Log']['created']),
                        'id' => $log['Log']['model_id']
                    ]
                )
            ];
            $objectMap['Event'][$log['Log']['model_id']] = true;
        }
    }

    private function __recoverDeletedObjects($id, &$objectMap, &$logEntries)
    {
        $logs = $this->find('all', [
            'recursive' => -1,
            'conditions' => [
                'model' => 'MispObject',
                'change LIKE ' => '%event_id () => (' . $id . ')%',
                'action' => ['add']
            ]
        ]);
        if (empty($logs)) {
            return;
        }
        foreach ($logs as $log) {
            $objectMap['MispObject'][$log['Log']['model_id']] = true;
        }
        $logs = $this->find('all', [
            'recursive' => -1,
            'conditions' => [
                'model' => 'MispObject',
                'model_id' => array_keys($objectMap['MispObject']),
                'action' => ['add', 'edit', 'delete']
            ]
        ]);
        foreach ($logs as $log) {
            $logEntries[$log['Log']['id']] = [
                'model_id' => $log['Log']['model_id'],
                'model' => $log['Log']['model'],
                'action' => $log['Log']['action'],
                'data' => array_merge(
                    $this->changeParser($log['Log']['change']),
                    [
                        'timestamp' => strtotime($log['Log']['created']),
                        'id' => $log['Log']['model_id']
                    ]
                )
            ];
        }
    }

    private function __recoverDeletedObjectReferences($id, &$objectMap, &$logEntries)
    {
        $logs = $this->find('all', [
            'recursive' => -1,
            'conditions' => [
                'model' => 'ObjectReference',
                'change LIKE ' => '%event_id () => (' . $id . ')%',
                'action' => ['add']
            ]
        ]);
        if (empty($logs)) {
            return;
        }
        foreach ($logs as $log) {
            $objectMap['ObjectReference'][$log['Log']['model_id']] = true;
        }
        $logs = $this->find('all', [
            'recursive' => -1,
            'conditions' => [
                'model' => 'ObjectReference',
                'model_id' => array_keys($objectMap['ObjectReference']),
                'action' => ['add', 'edit']
            ]
        ]);
        foreach ($logs as $log) {
            $logEntries[$log['Log']['id']] = [
                'model_id' => $log['Log']['model_id'],
                'model' => $log['Log']['model'],
                'action' => $log['Log']['action'],
                'data' => array_merge(
                    $this->changeParser($log['Log']['change']),
                    [
                        'timestamp' => strtotime($log['Log']['created']),
                        'id' => $log['Log']['model_id']
                    ]
                )
            ];
        }
    }

    private function __recoverDeletedTagConnectors($id, &$objectMap, &$logEntries, $scope)
    {
        if (empty($objectMap[$scope])) {
            // example: we have no attributes, so we return
            return;
        }
        $logs = $this->find('all', [
            'recursive' => -1,
            'conditions' => [
                'model' => $scope,
                'action' => ['tag', 'galaxy'],
                'model_id' => array_keys($objectMap[$scope])
            ]
        ]);
        if (empty($logs)) {
            return;
        }
        foreach ($logs as $log) {
            if ($log['Log']['action'] === 'tag') {
                $temp = explode(' ', $log['Log']['title']);
                $local = ($temp[1] === 'local' ? true : false);
                $tag_id = ($local ? $temp[3] : $temp[2]);
                $tag_id = substr($tag_id, 1, -1);
            } else {
                $matches = [];
                preg_match('/\(([0-9]*)\)\s(from|to)/', $log['Log']['title'], $matches);
                if (!isset($matches[1])) {
                    continue;
                }
                $local = false;
                $tag_id = $matches[1];
            }
            $logEntries[$log['Log']['id']] = [
                'model_id' => $log['Log']['model_id'],
                'model' => $log['Log']['model'],
                'action' => (strpos($log['Log']['title'], 'Attached')) === false ? 'remove_tag' : 'add_tag',
                'data' => [
                    'tag_id' => $tag_id,
                    'id' => $log['Log']['model_id'],
                    'target_type' => $log['Log']['model'],
                    'tag_type' => $log['Log']['action'],
                    'local' => $local
                ]
            ];
        }
    }

    private function __recoverDeletedAttributes($id, &$objectMap, &$logEntries)
    {
        $logs = $this->find('all', [
            'recursive' => -1,
            'conditions' => [
                'model' => 'Attribute',
                'title LIKE ' => '%from Event (' . $id . ')%',
                'action' => ['add']
            ]
        ]);
        if (empty($logs)) {
            return;
        }
        foreach ($logs as $log) {
            $objectMap['Attribute'][$log['Log']['model_id']] = true;
        }
        $logs = $this->find('all', [
            'recursive' => -1,
            'conditions' => [
                'model' => 'Attribute',
                'model_id' => array_keys($objectMap['Attribute']),
                'action' => ['add', 'edit', 'delete']
            ]
        ]);
        foreach ($logs as $log) {
            $logEntries[$log['Log']['id']] = [
                'model_id' => $log['Log']['model_id'],
                'model' => $log['Log']['model'],
                'action' => $log['Log']['action'],
                'data' => array_merge(
                    $this->changeParser($log['Log']['change']),
                    [
                        'timestamp' => strtotime($log['Log']['created']),
                        'id' => $log['Log']['model_id']
                    ]
                )
            ];
            $objectMap['Attribute'][$log['Log']['model_id']] = true;
        }
    }

    private function __recoverDeletedProposals($id, &$objectMap, &$logEntries)
    {
        $logs = $this->find('all', [
            'recursive' => -1,
            'conditions' => [
                'model' => 'ShadowAttribute',
                'title LIKE ' => '%: to Event (' . $id . '): %',
                'action' => ['add']
            ]
        ]);
        if (empty($logs)) {
            return;
        }
        foreach ($logs as $log) {
            $objectMap['ShadowAttribute'][$log['Log']['model_id']] = true;
        }
        $logs = $this->find('all', [
            'recursive' => -1,
            'conditions' => [
                'model' => 'ShadowAttribute',
                'model_id' => array_keys($objectMap['ShadowAttribute']),
                'action' => ['add', 'accept', 'delete']
            ]
        ]);
        foreach ($logs as $log) {
            $logEntries[$log['Log']['id']] = [
                'model_id' => $log['Log']['model_id'],
                'model' => $log['Log']['model'],
                'action' => $log['Log']['action'],
                'data' => array_merge(
                    $this->changeParser($log['Log']['change']),
                    [
                        'timestamp' => strtotime($log['Log']['created']),
                        'id' => $log['Log']['model_id']
                    ]
                )
            ];
            $objectMap['ShadowAttribute'][$log['Log']['model_id']] = true;
        }
    }


    private function __executeRecoveryEvent($logEntry, $id)
    {
        if (empty($this->Event)) {
            $this->Event = ClassRegistry::init('Event');
        }
        if (empty($this->GalaxyCluster)) {
            $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
        }
        if (empty($this->EventBlocklist)) {
            $this->EventBlocklist = ClassRegistry::init('EventBlocklist');
        }
        switch($logEntry['action']) {
            case 'add':
                if (!empty($this->mockRecovery)) {
                    $this->mockLog[] = ['model' => 'Event', 'action' => 'add', 'data' => $logEntry['data']];
                } else {
                    $this->Event->create();
                    $this->Event->save($logEntry['data']);
                    $blockListEntry = $this->EventBlocklist->find('first', array(
                        'conditions' => array('event_uuid' => $logEntry['data']['uuid']),
                        'fields' => 'id'
                    ));
                    if (!empty($blockListEntry)) {
                        $this->EventBlocklist->delete($blockListEntry['EventBlocklist']['id']);
                    }
                }
                break;
            case 'edit':
            case 'publish':
                $event = $this->Event->find('first', [
                    'recursive' => -1,
                    'conditions' => ['Event.id' => $logEntry['model_id']]
                ]);
                if (!empty($event)) {
                    if ($logEntry['action'] === 'publish' || $logEntry['action'] === 'alert') {
                        $event['Event']['published'] = 1;
                        $event['Event']['publish_timestamp'] = strtotime($logEntry['data']['timestamp']);
                    } else {
                        foreach ($logEntry['data'] as $field => $value) {
                            $event['Event'][$field] = $value;
                        }
                    }
                    $this->Event->create();
                    if (!empty($this->mockRecovery)) {
                        $this->mockLog[] = ['model' => 'Event', 'action' => 'edit', 'data' => $event];
                    } else {
                        $this->Event->save($event);
                    }
                }
                break;
            case 'add_tag':
                $tag_id = $logEntry['data']['tag_type'] === 'galaxy' ? $this->GalaxyCluster->getTagIdByClusterId($logEntry['data']['tag_id']) : $logEntry['data']['tag_id'];
                $this->Event->EventTag->create();
                $this->Event->create();
                if (!empty($this->mockRecovery)) {
                    $this->mockLog[] = ['model' => 'EventTag', 'action' => 'add', 'data' => [
                        'tag_id' => $tag_id,
                        'event_id' => $logEntry['data']['id'],
                        'local' => !empty($logEntry['data']['local'])
                    ]];
                } else {
                    $this->Event->EventTag->save([
                        'tag_id' => $tag_id,
                        'event_id' => $logEntry['data']['id'],
                        'local' => !empty($logEntry['data']['local'])
                    ]);
                }
                break;
            case 'remove_tag':
                $tag_id = $logEntry['data']['tag_type'] === 'galaxy' ? $this->GalaxyCluster->getTagIdByClusterId($logEntry['data']['tag_id']) : $logEntry['data']['tag_id'];
                $et = $this->Event->EventTag->find('first', [
                    'recursive' => -1,
                    'conditions' => [
                        'tag_id' => $tag_id,
                        'event_id' => $logEntry['data']['id']
                    ]
                ]);
                if (!empty($et)) {
                    if (!empty($this->mockRecovery)) {
                        $this->mockLog[] = ['model' => 'EventTag', 'action' => 'delete', 'data' => $et['EventTag']['id']];
                    } else {
                        $this->Event->EventTag->delete($et['EventTag']['id']);
                    }
                }
                break;
        }
    }

    private function __executeRecoveryAttribute($logEntry, $id)
    {
        if (empty($this->Attribute)) {
            $this->Attribute = ClassRegistry::init('Attribute');
        }
        if (empty($this->GalaxyCluster)) {
            $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
        }
        if (!empty($logEntry['data']['value1'])) {
            $logEntry['data']['value'] = $logEntry['data']['value1'];
            if (!empty($logEntry['data']['value2'])) {
                $logEntry .= '|' . $logEntry['data']['value2'];
            }
        }
        switch($logEntry['action']) {
            case 'add':
                $logEntry['data'] = $this->Attribute->UTCToISODatetime(['Attribute' => $logEntry['data']], 'Attribute');
                $logEntry['data'] = $logEntry['data']['Attribute'];
                if (!empty($this->mockRecovery)) {
                    $this->mockLog[] = ['model' => 'Attribute', 'action' => 'add', 'data' => $logEntry['data']];
                } else {
                    $this->Attribute->create();
                    if (!isset($logEntry['data']['to_ids'])) {
                        $logEntry['data']['to_ids'] = 0;
                    }
                    $this->Attribute->save($logEntry['data']);
                }
                break;
            case 'edit':
                $attribute = $this->Attribute->find('first', [
                    'recursive' => -1,
                    'conditions' => ['Attribute.id' => $logEntry['model_id']]
                ]);
                if (!empty($attribute)) {
                    $logEntry['data'] = $this->Attribute->UTCToISODatetime(['Attribute' => $logEntry['data']], 'Attribute');
                    $logEntry['data'] = $logEntry['data']['Attribute'];
                    foreach ($logEntry['data'] as $field => $value) {
                        $attribute['Attribute'][$field] = $value;
                    }
                    if (!empty($this->mockRecovery)) {
                        $this->mockLog[] = ['model' => 'Attribute', 'action' => 'edit', 'data' => $attribute];
                    } else {
                        $this->Attribute->save($attribute);
                    }
                }
                break;
            case 'delete':
                $attribute = $this->Attribute->find('first', [
                    'recursive' => -1,
                    'conditions' => ['Attribute.id' => $logEntry['model_id']]
                ]);
                if (!empty($attribute)) {
                    $attribute['Attribute']['deleted'] = 1;
                    $attribute['Attribute']['timestamp'] = $logEntry['data']['timestamp'];
                    if (!empty($this->mockRecovery)) {
                        $this->mockLog[] = ['model' => 'Attribute', 'action' => 'delete', 'data' => $attribute];
                    } else {
                        $this->Attribute->save($attribute);
                    }
                }
                break;
            case 'add_tag':
                $tag_id = $logEntry['data']['tag_type'] === 'galaxy' ? $this->GalaxyCluster->getTagIdByClusterId($logEntry['data']['tag_id']) : $logEntry['data']['tag_id'];
                if (!empty($this->mockRecovery)) {
                    $this->mockLog[] = ['model' => 'AttributeTag', 'action' => 'add', 'data' => [
                        'tag_id' => $tag_id,
                        'attribute_id' => $logEntry['data']['id'],
                        'event_id' => $id,
                        'local' => !empty($logEntry['data']['local'])
                    ]];
                } else {
                    $this->Attribute->AttributeTag->create();
                    $this->Attribute->AttributeTag->save([
                        'tag_id' => $tag_id,
                        'attribute_id' => $logEntry['data']['id'],
                        'event_id' => $id,
                        'local' => !empty($logEntry['data']['local'])
                    ]);
                }
                break;
            case 'remove_tag':
                $tag_id = $logEntry['data']['tag_type'] === 'galaxy' ? $this->GalaxyCluster->getTagIdByClusterId($logEntry['data']['tag_id']) : $logEntry['data']['tag_id'];
                $at = $this->Attribute->AttributeTag->find('first', [
                    'recursive' => -1,
                    'conditions' => [
                        'tag_id' => $tag_id,
                        'attribute_id' => $logEntry['data']['id'],
                        'event_id' => $id
                    ]
                ]);
                if (!empty($at)) {
                    if (!empty($this->mockRecovery)) {
                        $this->mockLog[] = ['model' => 'AttributeTag', 'action' => 'delete', 'data' => $at['AttributeTag']['id']];
                    } else {
                        $this->Attribute->AttributeTag->delete($at['AttributeTag']['id']);
                    }
                }
                break;
        }
    }

    private function __executeRecoveryShadowAttribute($logEntry, $id)
    {
        if (empty($this->Attribute)) {
            $this->Attribute = ClassRegistry::init('Attribute');
        }
        if (empty($this->ShadowAttribute)) {
            $this->ShadowAttribute = ClassRegistry::init('ShadowAttribute');
        }
        if (!empty($logEntry['data']['value1'])) {
            $logEntry['data']['value'] = $logEntry['data']['value1'];
            if (!empty($logEntry['data']['value2'])) {
                $logEntry .= '|' . $logEntry['data']['value2'];
            }
        }
        switch($logEntry['action']) {
            case 'add':
                $logEntry['data']['value'] = $logEntry['data']['value1'];
                if (!empty($logEntry['data']['value2'])) {
                    $logEntry['data']['value'] .= '|' . $logEntry['data']['value2'];
                }
                $logEntry['data'] = $this->Attribute->UTCToISODatetime(['ShadowAttribute' => $logEntry['data']], 'ShadowAttribute');
                if (!empty($this->mockRecovery)) {
                    $this->mockLog[] = ['model' => 'ShadowAttribute', 'action' => 'add', 'data' => $logEntry['data']];
                } else {
                    $this->ShadowAttribute->create();
                    $this->ShadowAttribute->save($logEntry['data']);
                }
                break;
            case 'delete':
                $shadow_attribute = $this->ShadowAttribute->find('first', [
                    'recursive' => -1,
                    'conditions' => ['ShadowAttribute.id' => $logEntry['model_id']]
                ]);
                if (!empty($shadow_attribute)) {
                    $shadow_attribute['ShadowAttribute']['deleted'] = 1;
                    $shadow_attribute['ShadowAttribute']['timestamp'] = $logEntry['data']['timestamp'];
                    if (!empty($this->mockRecovery)) {
                        $this->mockLog[] = ['model' => 'ShadowAttribute', 'action' => 'delete', 'data' => $attribute];
                    } else {
                        $this->ShadowAttribute->save($attribute);
                    }
                }
                break;
            case 'accept':
                $shadow_attribute = $this->ShadowAttribute->find('first', [
                    'recursive' => -1,
                    'conditions' => ['ShadowAttribute.id' => $logEntry['model_id']]
                ]);
                if (!empty($shadow_attribute['ShadowAttribute']['old_id'])) {
                    $attribute = $this->Attribute->find('first', [
                        'conditions' => ['Attribute.id' => $shadow_attribute['ShadowAttribute']['old_id']],
                        'recursive' => -1
                    ]);
                    if (!empty($shadow_attribute['ShadowAttribute']['proposal_to_delete'])) {
                        $attribute['Attribute']['deleted'] = 1;
                    } else {
                        foreach(['category', 'type', 'value', 'to_ids', 'comment', 'first_seen', 'last_seen'] as $field) {
                            if (isset($shadow_attribute['ShadowAttribute'][$field])) {
                                $attribute['Attribute'][$field] = $shadow_attribute['ShadowAttribute'][$field];
                            }
                        }
                    }
                    $attribute['Attribute']['timestamp'] = $logEntry['data']['timestamp'];
                    if (!empty($this->mockRecovery)) {
                        $this->mockLog[] = ['model' => 'Attribute', 'action' => 'edit', 'data' => $attribute];
                    } else {
                        $this->Attribute->save($attribute);
                    }
                } else {
                    $this->Attribute->create();
                    $attribute = $shadow_attribute['ShadowAttribute'];
                    if (isset($attribute['id'])) {
                        unset($attribute['id']);
                    }
                    if (!empty($this->mockRecovery)) {
                        $this->mockLog[] = ['model' => 'Attribute', 'action' => 'add', 'data' => $attribute];
                    } else {
                        $this->Attribute->save($attribute);
                    }
                }
                $shadow_attribute['ShadowAttribute']['deleted'] = 1;
                $shadow_attribute['ShadowAttribute']['timestamp'] = $logEntry['data']['timestamp'];
                if (!empty($this->mockRecovery)) {
                    $this->mockLog[] = ['model' => 'ShadowAttribute', 'action' => 'delete', 'data' => $shadow_attribute];
                } else {
                    $this->ShadowAttribute->save($shadow_attribute);
                }
                break;
        }
    }

    private function __executeRecoveryObjectReference($logEntry, $id)
    {
        if (empty($this->ObjectReference)) {
            $this->ObjectReference = ClassRegistry::init('ObjectReference');
        }
        switch($logEntry['action']) {
            case 'add':
                if (!empty($this->mockRecovery)) {
                    $this->mockLog[] = ['model' => 'ObjectReference', 'action' => 'add', 'data' => $logEntry['data']];
                } else {
                    $this->ObjectReference->create();
                    $this->ObjectReference->save($logEntry['data']);
                }
                break;
            case 'edit':
                $objectRef = $this->ObjectReference->find('first', [
                    'recursive' => -1,
                    'conditions' => ['ObjectReference.id' => $logEntry['model_id']]
                ]);
                if (!empty($object)) {
                    foreach ($logEntry['data'] as $field => $value) {
                        $object['ObjectReference'][$field] = $value;
                    }
                    if (!empty($this->mockRecovery)) {
                        $this->mockLog[] = ['model' => 'ObjectReference', 'action' => 'edit', 'data' => $object];
                    } else {
                        $this->ObjectReference->save($object);
                    }
                }
                break;
        }
    }

    private function __executeRecoveryMispObject($logEntry)
    {
        if (empty($this->Attribute)) {
            $this->Attribute = ClassRegistry::init('Attribute');
        }
        if (empty($this->MispObject)) {
            $this->MispObject = ClassRegistry::init('MispObject');
        }
        switch($logEntry['action']) {
            case 'add':
                $logEntry['data'] = $this->MispObject->Attribute->UTCToISODatetime(['Object' => $logEntry['data']], 'Object');
                $logEntry['data'] = $logEntry['data']['Object'];
                if (!empty($this->mockRecovery)) {
                    $this->mockLog[] = ['model' => 'MispObject', 'action' => 'add', 'data' => $logEntry['data']];
                } else {
                    $this->MispObject->create();
                    $this->MispObject->save($logEntry['data']);
                }
                break;
            case 'edit':
                $logEntry['data'] = $this->MispObject->Attribute->UTCToISODatetime(['Object' => $logEntry['data']], 'Object');
                $logEntry['data'] = $logEntry['data']['Object'];
                $object = $this->MispObject->find('first', [
                    'recursive' => -1,
                    'conditions' => ['Object.id' => $logEntry['model_id']]
                ]);
                if (!empty($object)) {
                    foreach ($logEntry['data'] as $field => $value) {
                        $object['Object'][$field] = $value;
                    }
                    if (!empty($this->mockRecovery)) {
                        $this->mockLog[] = ['model' => 'MispObject', 'action' => 'add', 'data' => $object];
                    } else {
                        $this->MispObject->save($object);
                    }
                }
                break;
        }
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
