<?php
App::uses('AppShell', 'Console/Command');
App::uses('ProcessTool', 'Tools');
App::uses('FileAccessTool', 'Tools');
App::uses('JsonTool', 'Tools');

/**
 * @property Server $Server
 * @property Feed $Feed
 * @property Warninglist $warninglist
 * @property AdminSetting $AdminSetting
 * @property Taxonomy $Taxonomy
 * @property Warninglist $Warninglist
 * @property MispAttribute $Attribute
 * @property Job $Job
 * @property Correlation $Correlation
 * @property OverCorrelatingValue $OverCorrelatingValue
 */
class AdminShell extends AppShell
{
    public $uses = [
        'Event',
        'Post',
        'MispAttribute',
        'Job',
        'User',
        'Task',
        'Allowedlist',
        'Server',
        'Organisation',
        'AdminSetting',
        'Galaxy',
        'Taxonomy',
        'Warninglist',
        'Noticelist',
        'ObjectTemplate',
        'Bruteforce',
        'Role',
        'Feed',
        'SharingGroupBlueprint',
        'Correlation',
        'OverCorrelatingValue'
    ];

    public function getOptionParser()
    {
        $parser = parent::getOptionParser();
        $parser->addSubcommand('updateJSON', array(
            'help' => __('Update the JSON definitions of MISP.'),
        ));
        $parser->addSubcommand('updateJSONLite', array(
            'help' => __('***TESTING ONLY*** Update the JSON definitions of MISP - but with a minimal set, only meant for testing.'),
        ));
        $parser->addSubcommand('checkUserValidity', array(
            'help' => __('Report users that the external identity provider no longer backs. Schedulable as an Admin task.'),
        ));
        $parser->addSubcommand('blockInvalidUsers', array(
            'help' => __('Disable users that the external identity provider no longer backs, and apply role and organisation changes. Schedulable as an Admin task.'),
        ));
        $parser->addSubcommand('updateWarningLists', array(
            'help' => __('Update the JSON definition of warninglists.'),
            'parser' => [
                'options' => [
                    'verbose' => [
                        'help' => 'Show verbose output.',
                        'default' => false,
                        'boolean' => true
                    ]
                ]
            ]
        ));
        $parser->addSubcommand('updateTaxonomies', array(
            'help' => __('Update the JSON definition of taxonomies.'),
        ));
        $parser->addSubcommand('setSetting', [
            'help' => __('Set setting in MISP config'),
            'parser' => [
                'arguments' => [
                    'name' => ['help' => __('Setting name'), 'required' => true],
                    'value' => ['help' => __('Setting value')],
                ],
                'options' => [
                    'force' => [
                        'short' => 'f',
                        'help' => 'Force the command.',
                        'default' => false,
                        'boolean' => true
                    ],
                    'null' => [
                        'short' => 'n',
                        'help' => 'Set the value to null.',
                        'default' => false,
                        'boolean' => true
                    ],
                ]
            ],
        ]);
        $parser->addSubcommand('live', [
            'help' => __('Set if MISP instance is live and accessible for users.'),
            'parser' => [
                'arguments' => [
                    'state' => ['help' => __('Set Live state (boolean). If not provided, current state will be printed.')],
                ],
            ],
        ]);
        $parser->addSubcommand('reencrypt', [
            'help' => __('Reencrypt encrypted values in database (authkeys and sensitive system settings).'),
            'parser' => [
                'options' => [
                    'old' => ['help' => __('Old key. If not provided, current key will be used.')],
                    'new' => ['help' => __('New key. If not provided, new key will be generated.')],
                ],
            ],
        ]);
        $parser->addSubcommand('isEncryptionKeyValid', [
            'help' => __('Check if current encryption key is valid.'),
            'parser' => [
                'options' => [
                    'encryptionKey' => ['help' => __('Encryption key to test. If not provided, current key will be used.')],
                ],
            ],
        ]);
        $parser->addSubcommand('dumpCurrentDatabaseSchema', [
            'help' => __('Dump current database schema to JSON file.'),
        ]);
        $parser->addSubcommand('updateAsnCountryMap', [
            'help' => __('Regenerate app/files/geo-open/asn-country.json from the GeoOpen-Country-ASN mmdb (requires the python maxminddb package). Run after the mmdb is updated; also part of preRelease.'),
        ]);
        $parser->addSubcommand('removeOrphanedCorrelations', [
            'help' => __('Remove orphaned correlations.'),
        ]);
        $parser->addSubcommand('optimiseTables', [
            'help' => __('Optimise database tables.'),
        ]);
        $parser->addSubcommand('redisMemoryUsage', [
            'help' => __('Get detailed information about Redis memory usage.'),
        ]);
        $parser->addSubcommand('redisReady', [
            'help' => __('Check if it is possible connect to Redis.'),
        ]);
        $parser->addSubcommand('securityAudit', [
            'help' => __('Run security audit.'),
        ]);
        $parser->addSubcommand('securityAuditTls', [
            'help' => __('Run security audit to test enabled/disabled ciphers and protocols in TLS connections.'),
        ]);
        $parser->addSubcommand('configLint', [
            'help' => __('Check if settings has correct value.'),
        ]);
        $parser->addSubcommand('createZmqConfig', [
            'help' => __('Create config file for ZeroMQ server.'),
        ]);
        $parser->addSubcommand('scanAttachment', [
            'help' => __('Scan attachments with AV.'),
            'parser' => [
                'arguments' => [
                    'type' => ['help' => __('all, Attribute or ShadowAttribute'), 'required' => true],
                    'attributeId' => ['help' => __('ID to scan.')],
                    'jobId' => ['help' => __('Job ID')],

                ],
            ],
        ]);
        $parser->addSubcommand('runDBScript', [
            'help' => __('Run a specific db script.'),
            'parser' => [
                'arguments' => [
                    'script' => ['help' => __('The name of the script to execute'), 'required' => false]
                ],
            ],
        ]);
        $parser->addSubcommand('preRelease', [
            'help' => __('Run the pre-release tasks (for developers).'),
        ]);
        $parser->addSubcommand('schemaDiagnostics', [
            'help' => __('Check differences between current and expected database schema')
        ]);
        $parser->addSubcommand('migrateOldTemplates', [
            'help' => __('Convert legacy-style templates (templates / template_elements*) into modern event_templates rows. Org name is resolved by lookup with the first site-admin user\'s org as fallback; legacy MISP-shipped templates are skipped; rows whose name collides with an existing event_template are skipped. Original templates are left untouched.'),
            'parser' => [
                'options' => [
                    'id' => [
                        'help' => __('Migrate only the legacy template with this id. Default: all eligible templates.'),
                    ],
                    'dry-run' => [
                        'short' => 'd',
                        'help' => __('Print the derived event_template definitions to stdout instead of inserting them.'),
                        'default' => false,
                        'boolean' => true,
                    ],
                    'export-dir' => [
                        'help' => __('Optional directory to write each derived definition.json into (created if it does not exist).'),
                    ],
                ],
            ],
        ]);
        return $parser;
    }

    public function jobForgot()
    {
        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['console_admin_tasks']['data']['Forgot'] . PHP_EOL);
        }

        $email = $this->args[0];
        $ip = empty($this->args[1]) ? null : $this->args[1];
        $jobId = empty($this->args[2]) ? null : $this->args[2];
        $this->User->forgot($email, $ip, $jobId);
    }

    public function jobGenerateCorrelation()
    {
        $jobId = $this->args[0] ?? null;
        $eventId = $this->args[1] ?? null;
        if (empty($jobId)) {
            $jobId = $this->Job->createJob(
                'SYSTEM',
                Job::WORKER_DEFAULT,
                'generate correlation',
                $eventId ? __('All attributes of event %d', $eventId) : __('All attributes'),
                'Job created.'
            );
        }

        $this->Correlation->generateCorrelation($jobId, $eventId);
    }

    public function jobGenerateOccurrences()
    {
        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['console_admin_tasks']['data']['Generate over-correlation occurrences'] . PHP_EOL);
        }

        $jobId = $this->args[0];
        $this->OverCorrelatingValue->generateOccurrences($jobId);
    }

    public function jobPurgeCorrelation()
    {
        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['console_admin_tasks']['data']['Purge correlation'] . PHP_EOL);
        }

        $jobId = $this->args[0];
        $this->Correlation->purgeCorrelations();
        $this->Job->saveStatus($jobId);
    }

    public function jobGenerateShadowAttributeCorrelation()
    {
        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['console_admin_tasks']['data']['Generate shadow attribute correlation'] . PHP_EOL);
        }

        $jobId = $this->args[0];
        $this->loadModel('Job');
        $this->Job->id = $jobId;
        $this->loadModel('ShadowAttribute');
        $this->ShadowAttribute->generateCorrelation($jobId);
    }

    public function updateMISP()
    {
        $status = array('branch' => '2.4');
        echo $this->Server->update($status) . PHP_EOL;
    }

    public function updateAfterPull()
    {
        if (empty($this->args[0]) || empty($this->args[1]) || empty($this->args[2])) {
            die('Usage: ' . $this->Server->command_line_functions['console_admin_tasks']['data']['Update after pull'] . PHP_EOL);
        }

        $this->loadModel('Job');
        $this->loadModel('Server');
        $submodule_name = $this->args[0];
        $jobId = $this->args[1];
        $userId = $this->args[2];
        $this->Job->id = $jobId;
        $result = $this->Server->updateAfterPull($submodule_name, $userId);
        $this->Job->saveField('progress', 100);
        $this->Job->saveField('date_modified', date("Y-m-d H:i:s"));
        if ($result) {
            $this->Job->saveField('message', __('Database updated: ' . $submodule_name));
        } else {
            $this->Job->saveField('message', __('Could not update the database: ' . $submodule_name));
        }
    }

    public function restartWorkers()
    {
        if (Configure::read('SimpleBackgroundJobs.enabled')) {
            try {
                $this->getBackgroundJobsTool()->restartWorkers(true);
            } catch (Throwable $e) {
                $this->error(__('Could not restart the workers'), $e->getMessage());
            }
        } else {
            $this->Server->restartWorkers();
        }
        echo PHP_EOL . 'Workers restarted.' . PHP_EOL;
    }

    public function restartWorker()
    {
        $simpleBackgroundJobs = (bool)Configure::read('SimpleBackgroundJobs.enabled');

        // Supervisor identifies its programs by name, CakeResque by PID.
        if (empty($this->args[0]) || (!$simpleBackgroundJobs && !is_numeric($this->args[0]))) {
            die('Usage: ' . $this->Server->command_line_functions['worker_management_tasks']['data']['Restart a worker'] . PHP_EOL);
        }

        $worker = $this->args[0];
        if ($simpleBackgroundJobs) {
            try {
                $tool = $this->getBackgroundJobsTool();
                $tool->stopWorker($worker, true);
                if (is_numeric($worker)) {
                    $tool->restartDeadWorkers(true);
                } else {
                    $tool->startWorker($worker, true);
                }
                $response = __('Worker restarted.');
            } catch (Throwable $e) {
                $response = __('Could not restart the worker. Reason: %s', $e->getMessage());
            }
        } else {
            $result = $this->Server->restartWorker($worker);
            if ($result === true) {
                $response = __('Worker restarted.');
            } else {
                $response = __('Could not restart the worker. Reason: %s', $result);
            }
        }
        echo sprintf(
            '%s%s%s',
            PHP_EOL,
            $response,
            PHP_EOL
        );
    }

    public function killWorker()
    {
        $simpleBackgroundJobs = (bool)Configure::read('SimpleBackgroundJobs.enabled');

        if (empty($this->args[0]) || (!$simpleBackgroundJobs && !is_numeric($this->args[0]))) {
            die('Usage: ' . $this->Server->command_line_functions['worker_management_tasks']['data']['Kill a worker'] . PHP_EOL);
        }

        $worker = $this->args[0];
        if ($simpleBackgroundJobs) {
            try {
                $this->getBackgroundJobsTool()->stopWorker($worker, true);
            } catch (Throwable $e) {
                $this->error(__('Could not kill the worker'), $e->getMessage());
            }
        } else {
            $this->Server->killWorker($worker, false);
        }
        echo sprintf(
            '%s%s%s',
            PHP_EOL,
            __('Worker killed.'),
            PHP_EOL
        );
    }

    public function startWorker()
    {
        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['worker_management_tasks']['data']['Start a worker'] . PHP_EOL);
        }

        $queue = $this->args[0];
        if (Configure::read('SimpleBackgroundJobs.enabled')) {
            try {
                if (!$this->getBackgroundJobsTool()->startWorkerByQueue($queue)) {
                    $this->error(__('Could not start a worker for queue %s', $queue), __('No stopped worker found for that queue.'));
                }
            } catch (Throwable $e) {
                $this->error(__('Could not start the worker'), $e->getMessage());
            }
        } else {
            $this->Server->startWorker($queue);
        }
        echo sprintf(
            '%s%s%s',
            PHP_EOL,
            __('Worker started.'),
            PHP_EOL
        );
    }

    public function updateJSONLite()
    {
        $this->out('Updating some JSON structures. I\'m travelling at the speed of light');
        $overallSuccess = true;
        foreach ($this->Server->updateJSON(true) as $type => $result) {
            $type = Inflector::pluralize(Inflector::humanize($type));
            if ($result['success']) {
                $this->out(__('%s updated in %.2f seconds.', $type, $result['duration']));
            } else {
                $this->out(__('Could not update %s.', $type));
                $this->out($result['result']);
                $overallSuccess = false;
            }
        }
        if ($overallSuccess) {
            $this->out('Some JSON structures updated. I wanna make a supersonic man out of you.');
        } else {
            $this->error('Some structure could no be updated');
        }
    }

    public function updateJSON()
    {
        $this->out('Updating all JSON structures.');

        $userId = empty($this->args[0])  ? null : $this->args[0];
        $jobId = empty($this->args[1])  ? null : $this->args[1];

        $overallSuccess = true;
        foreach ($this->Server->updateJSON() as $type => $result) {
            $type = Inflector::pluralize(Inflector::humanize($type));
            if ($result['success']) {
                $this->out(__('%s updated in %.2f seconds.', $type, $result['duration']));
            } else {
                $this->out(__('Could not update %s.', $type));
                $this->out($result['result']);
                $overallSuccess = false;
            }
        }
        if ($overallSuccess) {
            $this->out('All JSON structures updated. Thank you and have a very safe and productive day.');
            if (!is_null($jobId)) {
                $this->Job->saveProgress($jobId, 'All JSON structures updated', 100);
                $job['Job']['status'] = Job::STATUS_COMPLETED;
            }
        } else {
            $this->error('Some structure could no be updated');
            if (!is_null($jobId)) {
                $this->Job->saveStatus($jobId, false, 'Some JSON structures could not be updated');
            }
        }
    }

    public function updateGalaxies()
    {
        // The following is 7.x upwards only
        //$value = $this->args[0] ?? $this->args[0] ?? 0;
        $value = empty($this->args[0])  ? null : $this->args[0];
        $jobId = empty($this->args[1])  ? null : $this->args[1];
        if ($value === 'false') $value = 0;
        if ($value === 'true') $value = 1;
        if ($value === 'force') $value = 1;
        $force = $value;
        $result = $this->Galaxy->update($force);
        if ($result) {
            echo 'Galaxies updated' . PHP_EOL;
        } else {
            echo 'Could not update Galaxies' . PHP_EOL;
        }
        if (!is_null($jobId)) {
            $this->Job->saveStatus($jobId, true, 'Galaxies updated');
        }
    }

    public function updateTaxonomies()
    {
        $jobId = empty($this->args[0])  ? null : $this->args[0];
        $result = $this->Taxonomy->update();
        $successes = empty($result['success']) ? 0 : count($result['success']);
        $fails = empty($result['fails']) ? 0 : count($result['fails']);

        if ($successes === 0 && $fails === 0) {
            $message =  __('All taxonomies are up to date already.');
        } elseif ($successes === 0 && $fails > 0) {
            $message = __('Could not update any of the taxonomies.');
        } else {
            $message = __('Successfully updated %s taxonomies.', $successes);
            if ($fails !== 0) {
                $message .= __(' However, could not update %s taxonomies.', $fails);
            }
        }
        $this->out($message);
        if ($fails) {
            $this->out(__('Fails:'));
            foreach ($result['fails'] as $fail) {
                $this->out("{$fail['namespace']}: {$fail['fail']}");
            }
        }
        if (!is_null($jobId)) {
            $this->Job->saveStatus($jobId, true, $message);
        }
    }

    public function enableTaxonomyTags()
    {
        if (empty($this->args[0]) || !is_numeric($this->args[0])) {
            echo 'Usage: ' . APP . '/cake ' . 'Admin enableTaxonomyTags [taxonomy_id]' . PHP_EOL;
        } else {
            $result = $this->Taxonomy->addTags(intval($this->args[0]));
            if ($result) {
                echo 'Taxonomy tags enabled' . PHP_EOL;
            } else {
                echo 'Could not enable taxonomy tags' . PHP_EOL;
            }
        }
    }

    /**
     * Report which users the identity provider no longer backs. Changes nothing.
     */
    public function checkUserValidity()
    {
        $this->__runUserValidityCheck(false);
    }

    /**
     * Disable users the identity provider no longer backs, and apply role and
     * organisation changes it dictates.
     */
    public function blockInvalidUsers()
    {
        $this->__runUserValidityCheck(true);
    }

    /**
     * Both of the above, so a scheduled run and `cake User check_validity`
     * cannot diverge: this dispatches that command rather than repeating it.
     *
     * @param bool $enforce Disable invalid users and write back role/org.
     */
    private function __runUserValidityCheck($enforce)
    {
        $jobId = empty($this->args[0]) ? null : $this->args[0];

        $command = 'User check_validity';
        if ($enforce) {
            $command .= ' --block_invalid --update';
        }

        try {
            // The dispatched command prints a line per user, which the worker
            // captures as the job's output.
            $this->dispatchShell($command);
        } catch (Exception $e) {
            $message = __('User validity check failed: %s', $e->getMessage());
            $this->out($message);
            if ($jobId !== null) {
                $this->Job->saveStatus($jobId, false, $message);
            }
            $this->_stop(1);
            return;
        }

        $message = $enforce
            ? __('User validity check complete, invalid users disabled.')
            : __('User validity check complete, no changes made.');
        $this->out($message);
        if ($jobId !== null) {
            $this->Job->saveStatus($jobId, true, $message);
        }
    }

    public function updateWarningLists()
    {
        $jobId = empty($this->args[0]) ? null : $this->args[0];
        $result = $this->Warninglist->update();

        if ($this->params['verbose']) {
            $this->out($this->json($result));
        } else {
            $success = count($result['success']);
            $fails = count($result['fails']);
            $message = "$success warninglists updated, $fails fails";
            $this->out($message);
            if (!is_null($jobId)) {
                $this->Job->saveStatus($jobId, true, $message);
            }
            if ($fails) {
                $this->out(__('Fails:'));
                foreach ($result['fails'] as $fail) {
                    $this->out("{$fail['name']}: {$fail['fail']}");
                }
                $this->_stop(1);
            }
        }
    }

    public function updateNoticeLists()
    {
        $jobId = empty($this->args[0]) ? null : $this->args[0];
        $result = $this->Noticelist->update();
        if ($result) {
            echo 'Notice lists updated' . PHP_EOL;
            if (!is_null($jobId)) {
                $this->Job->saveStatus($jobId, true, 'Notice lists updated');
            }
        } else {
            echo 'Could not update notice lists' . PHP_EOL;
            if (!is_null($jobId)) {
                $this->Job->saveStatus($jobId, false, 'Could not update notice lists');
            }
        }
    }

    # FIXME: Fails to pass userId/orgId properly, global update works.
    public function updateObjectTemplates()
    {
        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['console_admin_tasks']['data']['Update object templates'] . PHP_EOL);
        } else {
            $userId = $this->args[0];
            $user = $this->User->getAuthUser($userId);
            # If the user_id passed does not exist, do a global update.
            if (empty($user)) {
                echo 'User with ID: ' . $userId . ' not found' . PHP_EOL;
                $result = $this->ObjectTemplate->update();
            } else {
                $result = $this->ObjectTemplate->update($user, false, false);
            }
            $jobId = empty($this->args[1]) ? null : $this->args[1];

            $successes = count(!empty($result['success']) ? $result['success'] : []);
            $fails = count(!empty($result['fails']) ? $result['fails'] : []);
            $message = '';
            if ($successes == 0 && $fails == 0) {
                $message = __('All object templates are up to date already.');
            } elseif ($successes == 0 && $fails > 0) {
                $message = __('Could not update any of the object templates.');
            } elseif ($successes > 0) {
                $message = __('Successfully updated %s object templates.', $successes);
                if ($fails != 0) {
                    $message .= __(' However, could not update %s object templates.', $fails);
                }
            }
            echo $message . PHP_EOL;

            if (!is_null($jobId)) {
                $this->Job->saveStatus($jobId, true, $message);
            }
        }
    }

    public function jobUpgrade24()
    {
        if (empty($this->args[0]) || empty($this->args[1])) {
            die('Usage: ' . $this->Server->command_line_functions['console_admin_tasks']['data']['Job upgrade'] . PHP_EOL);
        }

        $jobId = $this->args[0];
        $user_id = $this->args[1];
        $this->loadModel('Job');
        $this->Job->id = $jobId;
        $this->loadModel('Server');
        $this->Server->upgrade2324($user_id, $jobId);
        $this->Job->saveField('progress', 100);
        $this->Job->saveField('message', 'Job done.');
        $this->Job->saveField('status', 4);
    }

    public function prune_update_logs()
    {
        if (empty($this->args[0]) || empty($this->args[1])) {
            die('Usage: ' . $this->Server->command_line_functions['console_admin_tasks']['data']['Prune update logs'] . PHP_EOL);
        }

        $jobId = $this->args[0];
        $user_id = $this->args[1];
        $user = $this->User->getAuthUser($user_id);
        $this->loadModel('Job');
        $this->Job->id = $jobId;
        $this->loadModel('Log');
        $this->Log->pruneUpdateLogs($jobId, $user);
        $this->Job->saveField('progress', 100);
        $this->Job->saveField('message', 'Job done.');
        $this->Job->saveField('status', 4);
    }

    public function getWorkers()
    {
        $result = $this->Server->workerDiagnostics($workerIssueCount);
        $query = 'all';
        if (!empty($this->args[0])) {
            $query = $this->args[0];
        }
        if ($query === 'dead') {
            $dead_workers = array();
            foreach ($result as $queue => $data) {
                if (!empty($data['workers'])) {
                    foreach ($data['workers'] as $k => $worker) {
                        if ($worker['alive']) {
                            unset($result[$queue]['workers'][$k]);
                        }
                    }
                }
                if (empty($result[$queue]['workers'])) {
                    unset($result[$queue]);
                }
            }
        }
        echo json_encode($result, JSON_PRETTY_PRINT) . PHP_EOL;
    }

    public function getSetting()
    {
        $param = empty($this->args[0]) ? 'all' : $this->args[0];
        $settings = $this->Server->serverSettingsRead();
        $result = $settings;
        if ($param !== 'all') {
            $result = 'No valid setting found for ' . $param;
            foreach ($settings as $setting) {
                if ($setting['setting'] === $param) {
                    $result = $setting;
                    break;
                }
            }
        }
        $this->out($this->json($result));
    }

    public function setSetting()
    {
        list($settingName) = $this->args;

        if ($this->params['null'] && isset($this->args[1])) {
            $this->error(__('Trying to set setting to null value, but value was provided.'));
        } else if ($this->params['null']) {
            $value = null;
        } elseif (isset($this->args[1])) {
            $value = $this->args[1];
        } else {
            $this->error(__('No setting value provided.'));
        }

        $setting = $this->Server->getSettingData($settingName);
        if (empty($setting)) {
            $message = 'Invalid setting "' . $settingName . '". Please make sure that the setting that you are attempting to change exists and if a module parameter, the modules are running.' . PHP_EOL;
            $this->error(__('Setting change rejected.'), $message);
        }

        // Convert value to boolean or to int
        if ($value !== null) {
            if ($setting['type'] === 'boolean') {
                $value = $this->toBoolean($value);
            } else if ($setting['type'] === 'numeric') {
                if (is_numeric($value)) {
                    $value = (int)$value;
                } elseif ($value === 'true' || $value === 'false') {
                    $value = $value === 'true' ? 1 : 0; // special case for `debug` setting
                } else {
                    $this->error(__('Setting "%s" change rejected.', $settingName), __('Provided value %s is not a number.', $value));
                }
            }
        }

        $result = $this->Server->serverSettingsEditValue('SYSTEM', $setting, $value, $this->params['force'], true);
        if ($result === true) {
            $this->out(__('Setting "%s" changed to %s', $settingName, is_string($value) ? '"' . $value . '"' : json_encode($value)));
        } else {
            $message = __("The setting change was rejected. MISP considers the requested setting value as invalid and would lead to the following error:\n\n\"%s\"\n\nIf you still want to force this change, please supply the --force argument.\n", $result);
            $this->error(__('Setting change rejected.'), $message);
        }
    }

    public function setDatabaseVersion()
    {
        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['console_admin_tasks']['data']['Set database version'] . PHP_EOL);
        } else {
            $db_version = $this->AdminSetting->find('first', array(
                'conditions' => array('setting' => 'db_version')
            ));
            if (!empty($db_version)) {
                $db_version['AdminSetting']['value'] = trim($this->args[0]);
                $this->AdminSetting->save($db_version);
                echo 'Database version set. MISP will replay all of the upgrade scripts since the selected version on the next user login.' . PHP_EOL;
            } else {
                echo 'Something went wrong. Could not find the existing db version.' . PHP_EOL;
            }
        }
    }

    public function runUpdates()
    {
        $whoami = ProcessTool::whoami();
        $this->AdminSetting->resetUpdateFailNumber();
        if (in_array($whoami, ['httpd', 'www-data', 'apache', 'wwwrun', 'travis', 'www'], true) || $whoami === Configure::read('MISP.osuser')) {
            $this->out('Executing all updates to bring the database up to date with the current version.');
            $lock = $this->AdminSetting->find('first', array('conditions' => array('setting' => 'update_locked')));
            if (!empty($lock)) {
                $this->AdminSetting->delete($lock['AdminSetting']['id']);
            }
            $processId = empty($this->args[0]) ? false : $this->args[0];
            $this->Server->runUpdates(true, false, $processId, true);
            $this->Server->cleanCacheFiles();
            $this->out('All updates completed.');
        } else {
            $this->error('This OS user is not allowed to run this command.', 'Run it under `www-data` or `httpd` or `apache` or `wwwrun` or set MISP.osuser in the configuration.' . PHP_EOL . 'You tried to run this command as: ' . $whoami);
        }
    }

    public function runDBScript()
    {
        if (empty($this->args[0])) {
            $script = 'help';
        } else {
            $script = $this->args[0];
        }

        $aliasList = [
            'highPerformance' => [
                'scripts' => [
                    'highPerformanceIndexingEvents',
                    'highPerformanceIndexingAttributes',
                    'highPerformanceIndexingObjects',
                    'highPerformanceIndexingDefaultCorrelations',
                    'highPerformanceIndexingNoAclCorrelations',
                    'highPerformanceIndexingConnectorTags',
                    'highPerformanceIndexWarninglists'
                ],
                'help' => __('High performance indexing of events, attributes, objects and default correlations. Drastically improves view and search operations. This is a slow reindexing process and is meant for servers with abundant RAM and innodb_buffer_pool_size set to a high value.'),
            ],
            'indexLogs' => [
                'scripts' => [
                    'highPerformanceLogSearchIndexing',
                ],
                'help' => __('High performance indexing of logs. Drastically improves log search performance as well  as functionalities such as checking the past 10 logins. This is a slow reindexing process and is meant for servers with abundant RAM and innodb_buffer_pool_size set to a high value.'),
            ],
            'OnDemandCorrelationTuning' => [
                'scripts' => [
                    'OnDemandCorrelationTuning',
                ],
                'help' => __('Additional indices specifically to help with the unusual search patterns of the on demand correlation tuning.'),
            ]
        ];

        if (strtolower($script) === 'help') {
            $this->out('<info>' . __('Available scripts') . '</info>' . PHP_EOL);
            foreach ($aliasList as $alias => $data) {
                $this->out('<info>' . $alias . ':</info> <comment>' . $data['help'] . '</comment>' . PHP_EOL);
            }
            die('Usage: ' . $this->Server->command_line_functions['console_admin_tasks']['data']['Run DB Script'] . PHP_EOL);
            die();
        }

        if (isset($aliasList[$script])) {
            $scripts = $aliasList[$script]['scripts'];
            $count = count($scripts);
            foreach ($scripts as $i => $script) {
                $this->out('<info>' . sprintf('Executing script %s of %s: %s', $i + 1, $count, $script) . '</info>' . PHP_EOL);
                try {
                    $executed = $this->Server->updateDatabase($script);
                } catch (Exception $e) {
                    $this->out('<error>' . sprintf('Script %s of %s failed to execute. Skipping for now, check the audit logs for more.', $i + 1, $count) . '</error>' . PHP_EOL);
                    continue;
                }
                if ($executed) {
                    $this->out('<info>' . sprintf('Script %s of %s completed.', $i + 1, $count) . '</info>' . PHP_EOL);
                } else {
                    $this->out('<error>' . sprintf('Script %s of %s failed.', $i + 1, $count) . '</error>' . PHP_EOL);
                    $this->out(PHP_EOL . '<error>' . __('Invalid script') . '</error>' . PHP_EOL);
                    die();
                }
            }
        } else {
            $this->out(PHP_EOL . '<error>' . __('Invalid script') . '</error>' . PHP_EOL);
            die();
        }
        $this->Server->updateDatabase($script);
    }

    public function getAuthkey()
    {
        if (Configure::read("Security.advanced_authkeys")) {
            $this->error('Advanced authkeys enabled, it is not possible to get user authkey.');
        }
        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['console_admin_tasks']['data']['Get authkey'] . PHP_EOL);
        } else {
            $user = $this->User->find('first', array(
                'recursive' => -1,
                'conditions' => array('User.email' => strtolower($this->args[0])),
                'fields' => array('User.authkey')
            ));
            if (empty($user)) {
                echo 'Invalid user.' . PHP_EOL;
            } else {
                echo $user['User']['authkey'] . PHP_EOL;
            }
        }
    }

    public function redisReady()
    {
        try {
            $redis = RedisTool::init();
            for ($i = 0; $i < 10; $i++) {
                $pong = $redis->ping();
                if ($pong !== true) {
                    $this->out('Redis is still loading... ' . $pong);
                    sleep(1);
                } else {
                    break;
                }
            }
            if ($i === 9) {
                $this->out('Redis is still loading, but we will continue.');
            } else {
                $this->out('Successfully connected to Redis.');
            }
        } catch (Exception $e) {
            $this->error('Redis connection is not available', $e->getMessage());
        }
    }

    public function clearBruteforce()
    {
        $conditions = array('Bruteforce.username !=' => '');
        if (!empty($this->args[0])) {
            $conditions = array('Bruteforce.username' => $this->args[0]);
        }
        $result = $this->Bruteforce->deleteAll($conditions, false, false);
        $target = empty($this->args[0]) ? 'all users' : $this->args[0];
        if ($result) {
            echo 'Bruteforce entries for ' . $target . ' deleted.' . PHP_EOL;
        } else {
            echo 'Something went wrong, could not delete bruteforce entries for ' . $target . '.' . PHP_EOL;
        }
    }

    public function setDefaultRole()
    {
        if (empty($this->args[0]) || !is_numeric($this->args[0])) {
            $roles = $this->Role->find('list', array(
                'fields' => array('id', 'name')
            ));
            foreach ($roles as $k => $role) {
                $roles[$k] = $k . '. ' . $role;
            }
            $roles = implode(PHP_EOL, $roles);
            echo "Roles:\n" . $roles . $this->separator();
            die('Usage: ' . $this->Server->command_line_functions['console_admin_tasks']['data']['Set default role'] . PHP_EOL);
        } else {
            $role = $this->Role->find('first', array(
                'recursive' => -1,
                'conditions' => array('Role.id' => $this->args[0])
            ));
            if (!empty($role)) {
                $result = $this->AdminSetting->changeSetting('default_role', $role['Role']['id']);
                echo 'Default Role updated to ' . escapeshellcmd($role['Role']['name']) . PHP_EOL;
            } else {
                echo 'Something went wrong, invalid Role.' . PHP_EOL;
            }
        }
    }

    private function separator()
    {
        return PHP_EOL . '---------------------------------------------------------------' . PHP_EOL;
    }

    /**
     * @deprecated Use UserShell instead
     */
    public function change_authkey()
    {
        $this->deprecated('cake user change_authkey [user_id]');

        if (empty($this->args[0])) {
            echo 'MISP apikey command line tool' . PHP_EOL . 'To assign a new random API key for a user: ' . APP . 'Console/cake Admin change_authkey [user_email]' . PHP_EOL . 'To assign a fixed API key: ' . APP . 'Console/cake Admin change_authkey [user_email] [authkey]' . PHP_EOL;
            die();
        }

        if (!empty($this->args[1])) {
            $authKey = $this->args[1];
        } else {
            $authKey = $this->User->generateAuthKey();
        }
        $user = $this->User->find('first', array(
            'conditions' => array('email' => $this->args[0]),
            'recursive' => -1,
            'fields' => array('User.id', 'User.email', 'User.authkey')
        ));
        if (empty($user)) {
            echo 'Invalid e-mail, user not found.' . PHP_EOL;
            die();
        }
        $user['User']['authkey'] = $authKey;
        $fields = array('id', 'email', 'authkey');
        if (!$this->User->save($user, true, $fields)) {
            echo 'Could not update authkey, reason:' . PHP_EOL . json_encode($this->User->validationErrors) . PHP_EOL;
            die();
        }
        echo 'Updated, new key:' . PHP_EOL . $authKey . PHP_EOL;
    }

    public function recoverSinceLastSuccessfulUpdate()
    {
        $this->loadModel('Log');
        $logs = $this->Log->find('all', array(
            'conditions' => array(
                'action' => 'update_database',
                'title LIKE ' => array(
                    'Successfully executed the SQL query for %',
                    'Issues executing the SQL query for %'
                )
            ),
            'order' => 'id DESC'
        ));
        $last_db_num = -1;
        foreach ($logs as $i => $log) {
            preg_match_all('/.* the SQL query for (\d+)/', $log['Log']['title'], $matches);
            if (!empty($matches[1])) {
                $last_db_num = $matches[1][0];
                break;
            }
        }
        if ($last_db_num > 0) {
            echo __('Last DB num which was successfully executed: ') . h($last_db_num) . PHP_EOL;
            // replay all update from that point.
            $this->loadModel('AdminSetting');
            $db_version = $this->AdminSetting->find('first', array('conditions' => array('setting' => 'db_version')));
            if (!empty($db_version)) {
                $db_version['AdminSetting']['value'] = $last_db_num;
                $this->AdminSetting->save($db_version);
                $this->Server->runUpdates(true);
            } else {
                echo __('Something went wrong. Could not find the existing db version') . PHP_EOL;
            }
        } else {
            echo __('DB was never successfully updated or we are on a fresh install') . PHP_EOL;
        }
    }

    public function cleanCaches()
    {
        echo 'Cleaning caches...' . PHP_EOL;
        $this->Server->cleanCacheFiles();
        echo '...caches lost in time, like tears in rain.' . PHP_EOL;
    }

    public function resetSyncAuthkeys()
    {
        if (empty($this->args[0])) {
            echo sprintf(
                __("MISP mass sync authkey reset command line tool" . PHP_EOL . "Usage: %sConsole/cake Admin resetSyncAuthkeys [user_id]" . PHP_EOL),
                APP
            );
            die();
        } else {
            $userId = $this->args[0];
            $user = $this->User->getAuthUser($userId);
            if (empty($user)) {
                echo __('Invalid user.') . "\n\n";
            }
            if (!$user['Role']['perm_site_admin']) {
                echo __('User has to be a site admin.') . "\n\n";
            }
            if (!empty($this->args[1])) {
                $jobId = $this->args[1];
            } else {
                $jobId = false;
            }
            $this->User->resetAllSyncAuthKeys($user, $jobId);
        }
    }

    public function purgeFeedEvents()
    {
        if (
            (empty($this->args[0]) || !is_numeric($this->args[0])) ||
            (empty($this->args[1]) || !is_numeric($this->args[1]))
        ) {
            die('Usage: ' . $this->Server->command_line_functions['console_admin_tasks']['data']['Purge feed events'] . PHP_EOL);
        } else {
            $user_id = $this->args[0];
            $feed_id = $this->args[1];
            $result = $this->Feed->cleanupFeedEvents($user_id, $feed_id);
            if (is_string($result)) {
                echo __("\nError: %s\n", $result);
            } else {
                echo __("%s events purged.\n", $result);
            }
        }
    }

    public function dumpCurrentDatabaseSchema()
    {
        $dbActualSchema = $this->Server->getActualDBSchema();
        $dbVersion = $this->AdminSetting->getSetting('db_version');
        if (!empty($dbVersion) && !empty($dbActualSchema['schema'])) {
            $data = [
                'schema' => $dbActualSchema['schema'],
                'indexes' => $dbActualSchema['indexes'],
                'db_version' => $dbVersion,
            ];
            FileAccessTool::writeToFile(ROOT . DS . 'db_schema.json', JsonTool::encode($data, true));
            $this->out(__("> Database schema dumped on disk"));
        } else {
            $this->error(__('Something went wrong.'), __('Could not find the existing db version or fetch the current database schema.'));
        }
    }

    public function dumpDescribeTypes()
    {
        $data = $this->MispAttribute->describeTypes();
        $data = ['result' => $data];
        FileAccessTool::writeToFile(ROOT . DS . 'describeTypes.json', JsonTool::encode($data, true));
        $this->out(__("> describeTypes.json dumped to disk"));
    }

    public function updateAsnCountryMap()
    {
        $script = APP . 'files' . DS . 'scripts' . DS . 'generate_asn_country_map.py';
        try {
            $output = ProcessTool::execute([ProcessTool::pythonBin(), $script]);
            $this->out(__('> %s', trim($output)));
        } catch (Exception $e) {
            $this->err(__('> Could not regenerate asn-country.json: %s', $e->getMessage()));
            $this->err(__('> The shipped asn-country.json may be stale. Ensure the python maxminddb package is installed and GeoOpen-Country-ASN.mmdb is present.'));
        }
    }

    public function preRelease()
    {
        $this->out(__("Dumping database schema to disk"));
        $this->dumpCurrentDatabaseSchema();
        $this->out(__("Dumping describeTypes.json to disk"));
        $this->dumpDescribeTypes();
        $this->out(__("Regenerating asn-country.json from the GeoOpen-Country-ASN mmdb"));
        $this->updateAsnCountryMap();
    }

    /**
     * @deprecated Use UserShell instead
     */
    public function UserIP()
    {
        $this->deprecated('cake user user_ips [user_id]');

        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['console_admin_tasks']['data']['Get IPs for user ID'] . PHP_EOL);
        }

        $user_id = trim($this->args[0]);
        $results = $this->User->userIP($user_id);
        $ips = implode(PHP_EOL, $results['ips']);
        echo sprintf(
            '%s==============================%sUser #%s: %s%s==============================%s%s%s==============================%s',
            PHP_EOL,
            PHP_EOL,
            $results['User']['id'],
            $results['User']['email'],
            PHP_EOL,
            PHP_EOL,
            $ips,
            PHP_EOL,
            PHP_EOL
        );
    }

    /**
     * @deprecated Use UserShell instead
     */
    public function IPUser()
    {
        $this->deprecated('cake user ip_user [ip]');

        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['console_admin_tasks']['data']['Get user ID for user IP'] . PHP_EOL);
        }

        $ip = trim($this->args[0]);
        $results = $this->User->IPuser($ip);
        echo sprintf(
            '%s==============================%sIP: %s%s==============================%sUser #%s: %s%s==============================%s',
            PHP_EOL,
            PHP_EOL,
            $results['ip'],
            PHP_EOL,
            PHP_EOL,
            $results['User']['id'],
            $results['User']['email'],
            PHP_EOL,
            PHP_EOL
        );
    }

    public function scanAttachment()
    {
        $input = $this->args[0];
        $attributeId = $this->args[1] ?? null;
        $jobId = $this->args[2] ?? null;

        $this->loadModel('AttachmentScan');
        $result = $this->AttachmentScan->scan($input, $attributeId, $jobId);
        if ($result === false) {
            echo 'Job failed' . PHP_EOL;
        } else {
            echo $result . PHP_EOL;
        }
    }

    public function cleanExcludedCorrelations()
    {
        $jobId = $this->args[0];
        $this->CorrelationExclusion = ClassRegistry::init('CorrelationExclusion');
        $this->CorrelationExclusion->clean($jobId);
        $this->Job->id = $jobId;
        $this->Job->saveField('progress', 100);
        $this->Job->saveField('message', 'Job done.');
        $this->Job->saveField('status', 4);
    }

    public function removeOrphanedCorrelations()
    {
        $count = $this->Server->removeOrphanedCorrelations();
        $this->out(__('%s orphaned correlation removed', $count));
    }

    public function optimiseTables()
    {
        $dataSource = $this->Server->getDataSource();
        $tables = $dataSource->listSources();

        /** @var ProgressShellHelper $progress */
        $progress = $this->helper('progress');
        $progress->init([
            'total' => count($tables),
            'width' => 50,
        ]);

        foreach ($tables as $table) {
            $dataSource->query('OPTIMIZE TABLE ' . $dataSource->name($table));
            $progress->increment();
            $progress->draw();
        }

        $this->out('Optimised.');
    }

    public function updatesDone()
    {
        $blocking = !empty($this->args[0]);
        $done = $this->AdminSetting->updatesDone($blocking);
        $this->out($done ? 'True' : 'False');
    }

    public function wipeDefaultClusters()
    {
        $this->loadModel('GalaxyCluster');
        $this->out('Dropping default galaxy clusters. This process might take some time...');
        $this->GalaxyCluster->wipe_default();
    }

    public function updateToAdvancedAuthKeys()
    {
        $this->loadModel('User');
        $updated = $this->User->updateToAdvancedAuthKeys();
        $message = __('The upgrade process is complete, %s authkey(s) generated.', $updated);
        $this->out($message);
    }

    public function schemaDiagnostics()
    {
        $dbSchemaDiagnostics = $this->Server->dbSchemaDiagnostic();

        $this->out('# Columns diagnostics');
        foreach ($dbSchemaDiagnostics['diagnostic'] as $tableName => $diagnostics) {
            $diagnostics = array_filter($diagnostics, function ($c) {
                return $c['is_critical'];
            });
            if (empty($diagnostics)) {
                continue;
            }
            $this->out();
            $this->out("Table `$tableName`:");
            foreach ($diagnostics as $diagnostic) {
                $this->out(' - ' . $diagnostic['description']);
                $this->out('   Expected: ' . implode(' ', $diagnostic['expected']));
                if (!empty($diagnostic['actual'])) {
                    $this->out('   Actual:   ' . implode(' ', $diagnostic['actual']));
                }
            }
        }

        if (!empty($dbSchemaDiagnostics['diagnostic_index'])) {
            $this->out();
            $this->out('# Index diagnostics');
            foreach ($dbSchemaDiagnostics['diagnostic_index'] as $tableName => $diagnostics) {
                $this->out();
                $this->out('Table ' . $tableName . ':');
                foreach ($diagnostics as $info) {
                    $this->out(' - ' . $info['message']);
                }
            }
        }
    }

    public function live()
    {
        if (isset($this->args[0])) {
            $newStatus = $this->toBoolean($this->args[0]);
            $overallSuccess = false;
            try {
                $redis = RedisTool::init();
                if ($newStatus) {
                    $redis->del('misp:live');
                    $this->out('Set live status to True in Redis.');
                } else {
                    $redis->set('misp:live', '0');
                    $this->out('Set live status to False in Redis.');
                }
                $overallSuccess = true;
            } catch (Exception $e) {
                $this->out('<warning>Redis is not reachable.</warning>');
            }

            $success = $this->Server->serverSettingsSaveValue('MISP.live', $newStatus);
            if ($success) {
                $this->out('Set live status in PHP config file.');
                $overallSuccess = true;
            } else {
                $this->out('<warning>Could not set MISP.live in PHP config file.</warning>');
            }

            if ($overallSuccess) {
                $this->out($newStatus ? 'MISP is now live. Users can now log in.' : 'MISP is now disabled. Only site admins can log in.');
            } else {
                $this->error('Could not save live status in Redis or PHP config file.');
            }
        } else {
            $this->out('Current status:');
            $this->out('PHP Config file: ' . (Configure::read('MISP.live') ? 'True' : 'False'));
            $newStatus = RedisTool::init()->get('misp:live');
            $this->out('Redis: ' . ($newStatus !== '0' ? 'True' : 'False'));
        }
    }

    public function reencrypt()
    {
        $old = $this->params['old'] ?? null;
        $new = $this->params['new'] ?? null;

        if ($new !== null && strlen($new) < 32) {
            $this->error('New key must be at least 32 chars long.');
        }

        if ($old === null) {
            $old = Configure::read('Security.encryption_key');
        }

        if ($new === null) {
            // Generate random new key
            $new = rtrim(base64_encode(random_bytes(32)), "=");
        }

        $this->Server->getDataSource()->begin();

        try {
            /** @var SystemSetting $systemSetting */
            $systemSetting = ClassRegistry::init('SystemSetting');
            $systemSetting->reencrypt($old, $new);

            $this->Server->reencryptAuthKeys($old, $new);

            /** @var Cerebrate $cerebrate */
            $cerebrate = ClassRegistry::init('Cerebrate');
            $cerebrate->reencryptAuthKeys($old, $new);

            $result = $this->Server->serverSettingsSaveValue('Security.encryption_key', $new, true);

            $this->Server->getDataSource()->commit();

            if (!$result) {
                $this->error('Encrypt key was changed, but it is not possible to save key to config file', __('Please insert new key "%s" to config file manually.', $new));
            }
        } catch (Exception $e) {
            $this->Server->getDataSource()->rollback();
            throw $e;
        }

        $this->out(__('New encryption key "%s" saved into config file.', $new));
    }

    public function isEncryptionKeyValid()
    {
        $encryptionKey = $this->params['encryptionKey'] ?? null;
        if ($encryptionKey === null) {
            $encryptionKey = Configure::read('Security.encryption_key');
        }
        if (!$encryptionKey) {
            $this->error('No encryption key provided');
        }

        /** @var SystemSetting $systemSetting */
        $systemSetting = ClassRegistry::init('SystemSetting');

        try {
            $systemSetting->isEncryptionKeyValid($encryptionKey);
            $this->Server->isEncryptionKeyValid($encryptionKey);
        } catch (Exception $e) {
            $this->error($e->getMessage(), __('Probably provided encryption key is invalid'));
        }
    }

    public function redisMemoryUsage()
    {
        $redis = RedisTool::init();

        $output = [];

        list($count, $size) = RedisTool::sizeByPrefix($redis, 'misp:feed_cache:*');
        $output['feed_cache_count'] = $count;
        $output['feed_cache_size'] = $size;

        // Size of different feeds
        $feedIds = $this->Feed->find('column', [
            'fields' => ['id'],
        ]);

        $redis->pipeline();
        foreach ($feedIds as $feedId) {
            $redis->rawCommand("memory", "usage", 'misp:feed_cache:' . $feedId);
        }
        $feedSizes = $redis->exec();

        foreach ($feedIds as $k => $feedId) {
            if ($feedSizes[$k]) {
                $output['feed_cache_size_' . $feedId] = $feedSizes[$k];
            }
        }

        list($count, $size) = RedisTool::sizeByPrefix($redis, 'misp:server_cache:*');
        $output['server_cache_count'] = $count;
        $output['server_cache_size'] = $size;

        // Size of different server
        $serverIds = $this->Server->find('column', [
            'fields' => ['id'],
        ]);

        $redis->pipeline();
        foreach ($serverIds as $serverId) {
            $redis->rawCommand("memory", "usage", 'misp:server_cache:' . $serverId);
        }
        $serverSizes = $redis->exec();

        foreach ($serverIds as $k => $serverId) {
            if ($serverSizes[$k]) {
                $output['server_cache_size_' . $serverId] = $serverSizes[$k];
            }
        }

        list($count, $size) = RedisTool::sizeByPrefix($redis, 'misp:wlc:*');
        $output['warninglist_cache_count'] = $count;
        $output['warninglist_cache_size'] = $size;

        list($count, $size) = RedisTool::sizeByPrefix($redis, 'misp:warninglist_entries_cache:*');
        $output['warninglist_entries_count'] = $count;
        $output['warninglist_entries_size'] = $size;

        list($count, $size) = RedisTool::sizeByPrefix($redis, 'misp:top_correlation');
        $output['top_correlation_count'] = $count;
        $output['top_correlation_size'] = $size;

        list($count, $size) = RedisTool::sizeByPrefix($redis, 'misp:correlation_exclusions');
        $output['correlation_exclusions_count'] = $count;
        $output['correlation_exclusions_size'] = $size;

        list($count, $size) = RedisTool::sizeByPrefix($redis, 'misp:event_lock:*');
        $output['event_lock_count'] = $count;
        $output['event_lock_size'] = $size;

        list($count, $size) = RedisTool::sizeByPrefix($redis, 'misp:user_ip:*');
        $output['user_ip_count'] = $count;
        $output['user_ip_size'] = $size;

        list($count, $size) = RedisTool::sizeByPrefix($redis, 'misp:ip_user:*');
        $output['user_ip_count'] += $count;
        $output['user_ip_size'] += $size;

        list($count, $size) = RedisTool::sizeByPrefix($redis, 'misp:authkey_usage:*');
        $output['authkey_usage_count'] = $count;
        $output['authkey_usage_size'] = $size;

        $this->out($this->json($output));
    }

    public function securityAudit()
    {
        // Start session to initialize ini setting for session cookies
        CakeSession::start();
        CakeSession::destroy();

        $formatFindings = function (array $findings) {
            $value = '';
            foreach ($findings as $finding) {
                if ($finding[0] === 'error') {
                    $value .= '<error>Error:</error>';
                } else if ($finding[0] === 'warning') {
                    $value .= '<warning>Warning:</warning>';
                } else if ($finding[0] === 'hint') {
                    continue; // Ignore hints
                }

                $value .= ' ' . $finding[1] . PHP_EOL;
            }
            return $value;
        };

        App::uses('SecurityAudit', 'Tools');
        $securityAudit = (new SecurityAudit())->run($this->Server, true);
        foreach ($securityAudit as $field => $findings) {
            $value = $formatFindings($findings);
            if (!empty($value)) {
                $this->out($field);
                $this->out('==============================');
                $this->out($value);
            }
        }
    }

    public function securityAuditTls()
    {
        App::uses('SecurityAudit', 'Tools');
        $securityAudit = (new SecurityAudit())->tlsConnections();
        foreach ($securityAudit as $type => $details) {
            $result = $details['success'] ? 'True' : 'False';
            if (isset($details['expected']) && $details['expected'] !== $details['success']) {
                $result = "<error>$result</error>";
            }
            $this->out("$type: $result");
        }
    }

    public function configLint()
    {
        $serverSettings = $this->Server->serverSettingsRead();
        foreach ($serverSettings as $setting) {
            if (!isset($setting['error'])) {
                continue;
            }
            if ($setting['errorMessage'] === 'Value not set.') {
                continue; // Skip not set values.
            }
            $this->out($setting['setting'] . ': ' . $setting['errorMessage']);
        }
    }

    public function executeSGBlueprint()
    {
        $id = false;
        $target = 'all';
        if (!empty($this->args[0])) {
            $target = trim($this->args[0]);
        }
        if (!is_numeric($target) && !in_array($target, ['all', 'attached', 'detached'])) {
            $this->error(__('Invalid target. Either pass a blueprint ID or one of the following filters: all, attached, detached.'));
        }
        $conditions = [];
        if (is_numeric($target)) {
            $conditions['SharingGroupBlueprint']['id'] = $target;
        } else if ($target === 'attached') {
            $conditions['SharingGroupBlueprint']['sharing_group_id >'] = 0;
        } else if ($target === 'detached') {
            $conditions['SharingGroupBlueprint']['sharing_group_id'] = 0;
        }
        $sharingGroupBlueprints = $this->SharingGroupBlueprint->find('all', ['conditions' => $conditions, 'recursive' => 0]);
        if (empty($sharingGroupBlueprints)) {
            $this->error(__('No valid blueprints found.'));
        }
        $stats = $this->SharingGroupBlueprint->execute($sharingGroupBlueprints);
        $message = __(
            'Done, %s sharing group blueprint(s) matched. Sharing group changes: Created: %s. Updated: %s. Failed to create: %s.',
            count($sharingGroupBlueprints),
            $stats['created'],
            $stats['changed'],
            $stats['failed']
        );
        $this->out($message);
    }

    public function truncateTable()
    {
        if (!isset($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['console_admin_tasks']['data']['Truncate table correlation'] . PHP_EOL);
        }
        $userId = $this->args[0];
        if ($userId) {
            $user = $this->User->getAuthUser($userId);
        } else {
            $user = [
                'id' => 0,
                'email' => 'SYSTEM',
                'Organisation' => [
                    'name' => 'SYSTEM'
                ]
            ];
        }
        if (empty($this->args[1])) {
            die('Usage: ' . $this->Server->command_line_functions['console_admin_tasks']['data']['Truncate table correlation'] . PHP_EOL);
        }
        if (!empty($this->args[2])) {
            $jobId = $this->args[2];
        }
        $table = trim($this->args[1]);
        $this->Correlation->truncate($user, $table);
        if ($jobId) {
            $this->Job->id = $jobId;
            $this->Job->saveField('progress', 100);
            $this->Job->saveField('date_modified', date("Y-m-d H:i:s"));
            $this->Job->saveField('message', __('Database truncated: ' . $table));
        }
    }

    public function createZmqConfig()
    {
        $this->Server->getPubSubTool()->createConfigFile();
        $this->err("Config file created in " . PubSubTool::SCRIPTS_TMP);
    }

    /**
     * Convert legacy-style templates (templates / template_elements +
     * template_element_attributes / template_element_files /
     * template_element_texts) into modern event_templates rows.
     *
     * Mapping summary:
     *   templates.share=0 → event_templates.distribution=0 (your org)
     *   templates.share=1 → event_templates.distribution=1 (community)
     *   templates.org → event_templates.org_id (resolved by name; falls
     *     back to the first site-admin user's org_id when the name does
     *     not match any organisation row)
     *   text element → section element (label = old name, help = old text)
     *   attribute element (non-complex) → attribute_field (batch flag
     *     becomes repeatable; mandatory + category + type carry over;
     *     to_ids → to_ids_default)
     *   attribute element (complex File) → object_field referencing the
     *     misp-objects `file` template, relations: filename / md5 / sha1
     *     / sha256, repeatable (one instance per indicator). Legacy
     *     filename|<hash> composites collapse onto instances where the
     *     operator fills filename + hash on the same row.
     *   attribute element (complex CnC) → object_field referencing the
     *     misp-objects `domain-ip` template, relations: domain /
     *     hostname / ip, repeatable. Legacy `url` subtype is dropped
     *     (domain-ip has no url relation; reachable as a separate
     *     attribute_field if operators want it back).
     *   Both fall back to expanding into N attribute_fields with an
     *     inline text_block header when the named object template is
     *     not installed locally.
     *   file element → file_field (malware=1 → as: malware-sample,
     *     otherwise as: attachment)
     *   template_tags → event_defaults.tags (resolved to tag names).
     *
     * Legacy MISP-shipped templates (templates.org = "MISP" — the
     * Phishing E-mail / Malware Report seed set) are skipped because
     * the modern misp-event-templates library ships their successors.
     */
    public function migrateOldTemplates()
    {
        $idFilter = isset($this->params['id']) ? (int)$this->params['id'] : null;
        $dryRun = !empty($this->params['dry-run']);
        $exportDir = isset($this->params['export-dir']) && $this->params['export-dir'] !== ''
            ? rtrim((string)$this->params['export-dir'], '/')
            : null;

        $adminUser = $this->User->find('first', [
            'recursive' => -1,
            'contain' => ['Role'],
            'conditions' => ['Role.perm_site_admin' => 1, 'User.disabled' => 0],
            'order' => ['User.id' => 'ASC'],
        ]);
        if (empty($adminUser)) {
            $this->err('No active site-admin user found — cannot attribute the migration.');
            $this->_stop(1);
        }
        $userId = (int)$adminUser['User']['id'];
        $defaultOrgId = (int)$adminUser['User']['org_id'];

        $template = ClassRegistry::init('Template');
        $conditions = [];
        if ($idFilter !== null) {
            $conditions['Template.id'] = $idFilter;
        }
        $rows = $template->find('all', [
            'recursive' => -1,
            'conditions' => $conditions,
            'order' => ['Template.id' => 'ASC'],
        ]);
        if (empty($rows)) {
            $this->out('No legacy templates to migrate.');
            return;
        }

        if ($exportDir !== null && !is_dir($exportDir)) {
            if (!@mkdir($exportDir, 0755, true) && !is_dir($exportDir)) {
                $this->err('Could not create export directory: ' . $exportDir);
                $this->_stop(1);
            }
        }

        $eventTemplate = ClassRegistry::init('EventTemplate');
        $migrated = 0;
        $skipped = 0;
        $errors = 0;

        foreach ($rows as $row) {
            $tpl = $row['Template'];
            $name = (string)$tpl['name'];
            $oldOrg = trim((string)$tpl['org']);

            if (strtolower($oldOrg) === 'misp') {
                $this->out(sprintf('SKIP id=%d "%s" — legacy MISP-shipped template.', (int)$tpl['id'], $name));
                $skipped++;
                continue;
            }

            $existing = $eventTemplate->find('first', [
                'recursive' => -1,
                'conditions' => ['EventTemplate.name' => $name],
                'fields' => ['EventTemplate.id'],
            ]);
            if (!empty($existing)) {
                $this->out(sprintf(
                    'SKIP id=%d "%s" — event_template with same name already exists (id=%d).',
                    (int)$tpl['id'], $name, (int)$existing['EventTemplate']['id']
                ));
                $skipped++;
                continue;
            }

            $definition = $this->__buildEventTemplateDefinitionFromOld($tpl);
            $orgId = $this->__resolveOrgIdForOldTemplate($oldOrg, $defaultOrgId);

            $envelope = ['EventTemplate' => [
                'name' => $name,
                'description' => (string)$tpl['description'],
                'distribution' => ((int)$tpl['share'] === 1) ? 1 : 0,
                'active' => 1,
                'misp_default' => 0,
                'org_id' => $orgId,
                'creator_user_id' => $userId,
                'definition' => $definition,
            ]];

            if ($dryRun) {
                $this->out(sprintf('-- id=%d "%s" (would migrate) --', (int)$tpl['id'], $name));
                $this->out(json_encode($definition, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
                $migrated++;
            } else {
                $eventTemplate->create();
                $saved = $eventTemplate->save($envelope);
                if ($saved === false) {
                    $this->err(sprintf(
                        'FAIL id=%d "%s" — save returned validation errors: %s',
                        (int)$tpl['id'], $name,
                        json_encode($eventTemplate->validationErrors)
                    ));
                    $errors++;
                    continue;
                }
                $this->out(sprintf(
                    'OK   id=%d "%s" -> event_template id=%d',
                    (int)$tpl['id'], $name, (int)$eventTemplate->id
                ));
                $migrated++;
            }

            if ($exportDir !== null) {
                $slug = preg_replace('/[^a-z0-9]+/', '-', strtolower($name));
                $slug = trim((string)$slug, '-');
                if ($slug === '') {
                    $slug = 'template-' . (int)$tpl['id'];
                }
                $path = $exportDir . DS . $slug . '.json';
                file_put_contents(
                    $path,
                    json_encode($definition, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
                );
                $this->out('     exported to ' . $path);
            }
        }

        $this->out(sprintf(
            'Done. %s=%d skipped=%d errors=%d',
            $dryRun ? 'would-migrate' : 'migrated',
            $migrated, $skipped, $errors
        ));
    }

    /** @internal Build the new-style definition array from a legacy templates row. */
    private function __buildEventTemplateDefinitionFromOld(array $tpl)
    {
        App::uses('CakeText', 'Utility');
        $teModel = ClassRegistry::init('TemplateElement');
        $elements = $teModel->find('all', [
            'recursive' => -1,
            'conditions' => ['template_id' => (int)$tpl['id']],
            'order' => ['position' => 'ASC'],
        ]);

        $structure = [];
        $currentSection = null;
        $counters = ['sec' => 0, 'note' => 0, 'attr' => 0, 'file' => 0, 'obj' => 0];

        foreach ($elements as $entry) {
            $te = $entry['TemplateElement'];
            $type = strtolower((string)$te['element_definition']);
            $teId = (int)$te['id'];

            if ($type === 'text') {
                $row = $this->__loadTemplateElementChild('TemplateElementText', $teId);
                if ($row === null) {
                    continue;
                }
                $counters['sec']++;
                $secId = 'sec_' . $counters['sec'];
                $section = [
                    'type' => 'section',
                    'id' => $secId,
                    'label' => (string)($row['name'] ?? ''),
                ];
                $help = trim((string)($row['text'] ?? ''));
                if ($help !== '') {
                    $section['help'] = $help;
                }
                if ($section['label'] === '') {
                    // Schema requires a non-empty label — fall back so save doesn't fail.
                    $section['label'] = sprintf('Section %d', $counters['sec']);
                }
                $structure[] = $section;
                $currentSection = $secId;
                continue;
            }

            if ($type === 'attribute') {
                $row = $this->__loadTemplateElementChild('TemplateElementAttribute', $teId);
                if ($row === null) {
                    continue;
                }
                if (!empty($row['complex'])) {
                    // Complex File / CnC — emit a single object_field
                    // referencing the canonical misp-objects template
                    // for the group (file / domain-ip), repeatable so
                    // the operator can add one instance per indicator.
                    // Falls back to expanding into N attribute_fields if
                    // the object template is not installed locally.
                    $objSpec = $this->__resolveObjectTemplateForComplex((string)$row['type']);
                    if ($objSpec !== null) {
                        $counters['obj']++;
                        $field = [
                            'type' => 'object_field',
                            'id' => 'obj_' . $counters['obj'],
                            'label' => (string)$row['name'],
                            'mandatory' => !empty($row['mandatory']),
                            'repeatable' => true,
                            'object_template' => [
                                'uuid' => $objSpec['uuid'],
                                'name' => $objSpec['name'],
                                'minimum_version' => $objSpec['version'],
                            ],
                            'relations' => array_map(function ($rel) {
                                return ['object_relation' => $rel];
                            }, $objSpec['relations']),
                        ];
                        if ($currentSection !== null) {
                            $field['parent'] = $currentSection;
                        }
                        if (!empty($row['description'])) {
                            $field['help'] = (string)$row['description'];
                        }
                        $structure[] = $field;
                        continue;
                    }

                    // Fallback path — emit an inline note + one
                    // attribute_field per subtype, all under the current
                    // section (no new section so a subsequent non-complex
                    // attribute stays grouped with the original).
                    $counters['note']++;
                    $noteContent = sprintf(
                        '**%s** — capture any combination of the matching subtypes below.',
                        (string)$row['name']
                    );
                    if (!empty($row['description'])) {
                        $noteContent .= "\n\n" . (string)$row['description'];
                    }
                    $structure[] = [
                        'type' => 'text_block',
                        'id' => 'note_' . $counters['note'],
                        'content' => $noteContent,
                    ];
                    foreach ($this->__expandComplexAttributeType((string)$row['type']) as $sub) {
                        $counters['attr']++;
                        $field = [
                            'type' => 'attribute_field',
                            'id' => 'attr_' . $counters['attr'],
                            'label' => (string)$row['name'] . ' — ' . $sub['label'],
                            'mandatory' => false,
                            'repeatable' => true,
                            'misp' => [
                                'category' => (string)$row['category'],
                                'type' => $sub['type'],
                                'to_ids_default' => !empty($row['to_ids']),
                            ],
                        ];
                        if ($currentSection !== null) {
                            $field['parent'] = $currentSection;
                        }
                        $structure[] = $field;
                    }
                    continue;
                }

                // Regular attribute → single attribute_field.
                $counters['attr']++;
                $repeatable = !empty($row['batch']);
                $field = [
                    'type' => 'attribute_field',
                    'id' => 'attr_' . $counters['attr'],
                    'label' => (string)$row['name'],
                    'mandatory' => !empty($row['mandatory']),
                    'repeatable' => $repeatable,
                    'misp' => [
                        'category' => (string)$row['category'],
                        'type' => (string)$row['type'],
                        'to_ids_default' => !empty($row['to_ids']),
                    ],
                ];
                if ($currentSection !== null) {
                    $field['parent'] = $currentSection;
                }
                if (!empty($row['description'])) {
                    $field['help'] = (string)$row['description'];
                }
                if ($field['label'] === '') {
                    $field['label'] = sprintf('Attribute %d', $counters['attr']);
                }
                $structure[] = $field;
                continue;
            }

            if ($type === 'file') {
                $row = $this->__loadTemplateElementChild('TemplateElementFile', $teId);
                if ($row === null) {
                    continue;
                }
                $counters['file']++;
                $field = [
                    'type' => 'file_field',
                    'id' => 'file_' . $counters['file'],
                    'label' => (string)$row['name'],
                    'mandatory' => !empty($row['mandatory']),
                    'repeatable' => !empty($row['batch']),
                    'as' => !empty($row['malware']) ? 'malware-sample' : 'attachment',
                ];
                if ($currentSection !== null) {
                    $field['parent'] = $currentSection;
                }
                if (!empty($row['description'])) {
                    $field['help'] = (string)$row['description'];
                }
                if ($field['label'] === '') {
                    $field['label'] = sprintf('File %d', $counters['file']);
                }
                $structure[] = $field;
            }
        }

        // Resolve template_tags to event_defaults.tags (by tag name).
        $eventDefaults = ['distribution' => ((int)$tpl['share'] === 1) ? 1 : 0];
        $templateTagModel = ClassRegistry::init('TemplateTag');
        $tagModel = ClassRegistry::init('Tag');
        $links = $templateTagModel->find('all', [
            'recursive' => -1,
            'conditions' => ['template_id' => (int)$tpl['id']],
        ]);
        $tagEntries = [];
        foreach ($links as $link) {
            $tagId = (int)$link['TemplateTag']['tag_id'];
            $tagRow = $tagModel->find('first', [
                'recursive' => -1,
                'conditions' => ['Tag.id' => $tagId],
                'fields' => ['Tag.name'],
            ]);
            if (!empty($tagRow['Tag']['name'])) {
                $tagEntries[] = ['name' => (string)$tagRow['Tag']['name'], 'locked' => false];
            }
        }
        if (!empty($tagEntries)) {
            $eventDefaults['tags'] = $tagEntries;
        }

        return [
            'schema_version' => 1,
            'uuid' => CakeText::uuid(),
            'name' => (string)$tpl['name'],
            'description' => (string)$tpl['description'],
            'event_defaults' => $eventDefaults,
            'structure' => $structure,
        ];
    }

    private function __loadTemplateElementChild($modelName, $teId)
    {
        $model = ClassRegistry::init($modelName);
        $row = $model->find('first', [
            'recursive' => -1,
            'conditions' => ['template_element_id' => (int)$teId],
        ]);
        return isset($row[$modelName]) ? $row[$modelName] : null;
    }

    /**
     * @internal
     * Resolve a legacy complex attribute group (File / CnC) to a misp-objects
     * template + the relations we want exposed in the new template's
     * object_field. Returns null if the template is not installed locally,
     * which the caller treats as a signal to fall back to multi
     * attribute_field expansion.
     *
     *   File → file object (filename, md5, sha1, sha256). The legacy
     *     filename|md5 / |sha1 / |sha256 composites collapse onto an
     *     instance where the operator fills both filename and the
     *     hash, since object relations are atomic.
     *   CnC  → domain-ip object (domain, hostname, ip). The legacy
     *     `url` subtype is dropped — domain-ip has no url relation,
     *     and operators wanting url indicators can add an
     *     attribute_field manually.
     */
    private function __resolveObjectTemplateForComplex($type)
    {
        $key = strtolower(trim((string)$type));
        $map = [
            'file' => [
                'uuid' => '688c46fb-5edb-40a3-8273-1af7923e2215',
                'name' => 'file',
                'relations' => ['filename', 'md5', 'sha1', 'sha256'],
            ],
            'cnc' => [
                'uuid' => '43b3b146-77eb-4931-b4cc-b66c60f28734',
                'name' => 'domain-ip',
                'relations' => ['domain', 'hostname', 'ip'],
            ],
        ];
        if (!isset($map[$key])) {
            return null;
        }
        $spec = $map[$key];
        $row = $this->ObjectTemplate->find('first', [
            'recursive' => -1,
            'conditions' => array(
                'ObjectTemplate.uuid' => $spec['uuid'],
                'ObjectTemplate.active' => true,
            ),
            'fields' => ['ObjectTemplate.version'],
            'order' => ['ObjectTemplate.version' => 'DESC'],
        ]);
        if (empty($row)) {
            return null;
        }
        $spec['version'] = (int)$row['ObjectTemplate']['version'];
        return $spec;
    }

    /** @internal Expand a legacy complex attribute (File / CnC) into its concrete subtypes. */
    private function __expandComplexAttributeType($type)
    {
        $key = strtolower(trim((string)$type));
        if ($key === 'file') {
            return [
                ['label' => 'Filename', 'type' => 'filename'],
                ['label' => 'MD5', 'type' => 'md5'],
                ['label' => 'SHA1', 'type' => 'sha1'],
                ['label' => 'SHA256', 'type' => 'sha256'],
                ['label' => 'Filename | MD5', 'type' => 'filename|md5'],
                ['label' => 'Filename | SHA1', 'type' => 'filename|sha1'],
                ['label' => 'Filename | SHA256', 'type' => 'filename|sha256'],
            ];
        }
        if ($key === 'cnc') {
            return [
                ['label' => 'URL', 'type' => 'url'],
                ['label' => 'Domain', 'type' => 'domain'],
                ['label' => 'Hostname', 'type' => 'hostname'],
                ['label' => 'IP destination', 'type' => 'ip-dst'],
            ];
        }
        // Unknown complex type — fall back to a single attribute_field so the
        // operator can still see the row and adjust manually.
        return [['label' => (string)$type, 'type' => 'text']];
    }

    private function __resolveOrgIdForOldTemplate($name, $fallbackOrgId)
    {
        if ($name === '') {
            return (int)$fallbackOrgId;
        }
        $row = $this->Organisation->find('first', [
            'recursive' => -1,
            'conditions' => ['Organisation.name' => $name],
            'fields' => ['Organisation.id'],
        ]);
        if (!empty($row['Organisation']['id'])) {
            return (int)$row['Organisation']['id'];
        }
        return (int)$fallbackOrgId;
    }
}
