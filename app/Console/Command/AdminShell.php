<?php
App::uses('AppShell', 'Console/Command');
class AdminShell extends AppShell
{
    public $uses = array('Event', 'Post', 'Attribute', 'Job', 'User', 'Task', 'Allowedlist', 'Server', 'Organisation', 'AdminSetting', 'Galaxy', 'Taxonomy', 'Warninglist', 'Noticelist', 'ObjectTemplate', 'Bruteforce', 'Role', 'Feed');

    public $tasks = array('ConfigLoad');

    public function jobGenerateCorrelation()
    {
        $this->ConfigLoad->execute();
        $jobId = $this->args[0];
        $this->loadModel('Job');
        $this->Job->id = $jobId;
        $this->loadModel('Attribute');
        $this->Attribute->generateCorrelation($jobId, 0);
        $this->Job->saveField('progress', 100);
        $this->Job->saveField('message', 'Job done.');
        $this->Job->saveField('status', 4);
    }

    public function jobPurgeCorrelation()
    {
        $this->ConfigLoad->execute();
        $jobId = $this->args[0];
        $this->loadModel('Job');
        $this->Job->id = $jobId;
        $this->loadModel('Attribute');
        $this->Attribute->purgeCorrelations();
        $this->Job->saveField('progress', 100);
        $this->Job->saveField('message', 'Job done.');
        $this->Job->saveField('status', 4);
    }

    public function jobGenerateShadowAttributeCorrelation()
    {
        $this->ConfigLoad->execute();
        $jobId = $this->args[0];
        $this->loadModel('Job');
        $this->Job->id = $jobId;
        $this->loadModel('ShadowAttribute');
        $this->ShadowAttribute->generateCorrelation($jobId);
    }

    public function updateMISP()
    {
        $this->ConfigLoad->execute();
        $status = array('branch' => '2.4');
        echo $this->Server->update($status) . PHP_EOL;
    }

    public function restartWorkers()
    {
        $this->ConfigLoad->execute();
        $this->Server->restartWorkers();
        echo PHP_EOL . 'Workers restarted.' . PHP_EOL;
    }

    public function updateAfterPull()
    {
        $this->ConfigLoad->execute();
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

    public function restartWorker()
    {
        $this->ConfigLoad->execute();
        if (empty($this->args[0]) || !is_numeric($this->args[0])) {
            echo 'Usage: ' . APP . '/cake ' . 'Admin restartWorker [PID]' . PHP_EOL;
        }
        $pid = $this->args[0];
        $result = $this->Server->restartWorker($pid);
        if ($result === true) {
            $response = __('Worker restarted.');
        } else {
            $response = __('Could not restart the worker. Reason: %s', $result);
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
        $this->ConfigLoad->execute();
        if (empty($this->args[0]) || !is_numeric($this->args[0])) {
            echo 'Usage: ' . APP . '/cake ' . 'Admin killWorker [PID]' . PHP_EOL;
            die();
        }
        $pid = $this->args[0];
        $result = $this->Server->killWorker($pid, false);
        echo sprintf(
            '%s%s%s',
            PHP_EOL,
            __('Worker killed.'),
            PHP_EOL
        );
    }

    public function startWorker()
    {
        $this->ConfigLoad->execute();
        if (empty($this->args[0])) {
            echo 'Usage: ' . APP . '/cake ' . 'Admin startWorker [queue]' . PHP_EOL;
            die();
        }
        $queue = $this->args[0];
        $this->Server->startWorker($queue);
        echo sprintf(
            '%s%s%s',
            PHP_EOL,
            __('Worker started.'),
            PHP_EOL
        );
    }

    public function updateJSON()
    {
        $this->ConfigLoad->execute();
        echo 'Updating all JSON structures.' . PHP_EOL;
        $results = $this->Server->updateJSON();
        foreach ($results as $type => $result) {
            if ($result !== false) {
                echo sprintf(
                    __('%s updated.') . PHP_EOL,
                    Inflector::pluralize(Inflector::humanize($type))
                );
            } else {
                echo sprintf(
                    __('Could not update %s.') . PHP_EOL,
                    Inflector::pluralize(Inflector::humanize($type))
                );
            }
        }
        echo 'All JSON structures updated. Thank you and have a very safe and productive day.' . PHP_EOL;
    }

    public function updateGalaxies()
    {
        $this->ConfigLoad->execute();
        // The following is 7.x upwards only
        //$value = $this->args[0] ?? $this->args[0] ?? 0;
        $value = empty($this->args[0])  ? null : $this->args[0];
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
    }

    # FIXME: Make Taxonomy->update() return a status string on API if successful
    public function updateTaxonomies()
    {
        $this->ConfigLoad->execute();
        $result = $this->Taxonomy->update();
        if ($result) {
            echo 'Taxonomies updated' . PHP_EOL;
        } else {
            echo 'Could not update Taxonomies' . PHP_EOL;
        }
    }

    public function updateWarningLists()
    {
        $this->ConfigLoad->execute();
        $result = $this->Warninglist->update();
        $success = count($result['success']);
        $fails = count($result['fails']);
        echo "$success warninglists updated, $fails fails" . PHP_EOL;
    }

    public function updateNoticeLists()
    {
        $this->ConfigLoad->execute();
        $result = $this->Noticelist->update();
        if ($result) {
            echo 'Notice lists updated' . PHP_EOL;
        } else {
            echo 'Could not update notice lists' . PHP_EOL;
        }
    }

    # FIXME: Fails to pass userId/orgId properly, global update works.
    public function updateObjectTemplates()
    {
        $this->ConfigLoad->execute();
        if (empty($this->args[0])) {
            echo 'Usage: ' . APP . '/cake ' . 'Admin updateObjectTemplates [user_id]' . PHP_EOL;
        } else {
            $userId = $this->args[0];
            $user = $this->User->getAuthUser($userId);
            # If the user_id passed does not exist, do a global update.
            if (empty($user)) {
                echo 'User with ID: ' . $userId . ' not found' . PHP_EOL;
                $result = $this->ObjectTemplate->update();
            } else {
                $result = $this->ObjectTemplate->update($user, false,false);
            }

            $successes = count(!empty($result['success']) ? $result['success'] : []);
            $fails = count(!empty($result['fails']) ? $result['fails'] : []);
            $message = '';
            if ($successes == 0 && $fails == 0) {
                $message = __('All object templates are up to date already.');
            } elseif ($successes == 0 && $fails > 0) {
                $message = __('Could not update any of the object templates.');
            } elseif ($successes > 0 ) {
                $message = __('Successfully updated %s object templates.', $successes);
                if ($fails != 0) {
                    $message .= __(' However, could not update %s object templates.', $fails);
                }
            }
            echo $message . PHP_EOL;
        }
    }

    public function jobUpgrade24()
    {
        $this->ConfigLoad->execute();
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
        $this->ConfigLoad->execute();
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
        $this->ConfigLoad->execute();
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
        $this->ConfigLoad->execute();
        $param = empty($this->args[0]) ? 'all' : $this->args[0];
        $settings = $this->Server->serverSettingsRead();
        $result = $settings;
        if ($param != 'all') {
            $result = 'No valid setting found for ' . $param;
            foreach ($settings as $setting) {
                if ($setting['setting'] == $param) {
                    $result = $setting;
                    break;
                }
            }
        }
        echo json_encode($result, JSON_PRETTY_PRINT) . PHP_EOL;
  }

    public function setSetting()
    {
        $this->ConfigLoad->execute();
        $setting_name = !isset($this->args[0]) ? null : $this->args[0];
        $value = !isset($this->args[1]) ? null : $this->args[1];
        if ($value === 'false') $value = 0;
        if ($value === 'true') $value = 1;
        $cli_user = array('id' => 0, 'email' => 'SYSTEM', 'Organisation' => array('name' => 'SYSTEM'));
        if (empty($setting_name) || $value === null) {
            echo 'Invalid parameters. Usage: ' . APP . 'Console/cake Admin setSetting [setting_name] [setting_value]' . PHP_EOL;
        } else {
            $setting = $this->Server->getSettingData($setting_name);
            if (empty($setting)) {
                echo 'Invalid setting "' . $setting_name . '". Please make sure that the setting that you are attempting to change exists and if a module parameter, the modules are running.' . PHP_EOL;
                exit(1);
            }
            $result = $this->Server->serverSettingsEditValue($cli_user, $setting, $value);
            if ($result === true) {
                echo 'Setting "' . $setting_name . '" changed to ' . $value . PHP_EOL;
            } else {
                echo $result;
            }
        }
        echo PHP_EOL;
    }

    public function setDatabaseVersion()
    {
        $this->ConfigLoad->execute();
        if (empty($this->args[0])) echo 'Invalid parameters. Usage: ' . APP . 'Console/cake Admin setDatabaseVersion [db_version]' . PHP_EOL;
        else {
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
        $this->ConfigLoad->execute();
        $whoami = exec('whoami');
        $osuser = Configure::read('MISP.osuser');
        if ($whoami === 'httpd' || $whoami === 'www-data' || $whoami === 'apache' || $whoami === 'wwwrun' || $whoami === 'travis' || $whoami === 'www' || $whoami === $osuser) {
            echo 'Executing all updates to bring the database up to date with the current version.' . PHP_EOL;
            $processId = empty($this->args[0]) ? false : $this->args[0];
            $this->Server->runUpdates(true, false, $processId);
            echo 'All updates completed.' . PHP_EOL;
        } else {
            die('This OS user is not allowed to run this command.'. PHP_EOL. 'Run it under `www-data` or `httpd` or `apache` or `wwwrun` or set MISP.osuser in the configuration.' . PHP_EOL . 'You tried to run this command as: ' . $whoami . PHP_EOL);
        }
    }

    public function getAuthkey()
    {
        $this->ConfigLoad->execute();
        if (empty($this->args[0])) {
            echo 'Invalid parameters. Usage: ' . APP . 'Console/cake Admin getAuthkey [user_email]' . PHP_EOL;
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

    public function clearBruteforce()
    {
        $this->ConfigLoad->execute();
        $conditions = array('Bruteforce.username !=' => '');
        if (!empty($this->args[0])) {
            $conditions = array('Bruteforce.username' => $this->args[0]);
        }
        $result = $this->Bruteforce->deleteAll($conditions, false, false);
        $target = empty($this->args[0]) ? 'all users' : $this->args[0];
        if ($result) {
            echo 'Brutefoce entries for ' . $target . ' deleted.' . PHP_EOL;
        } else {
            echo 'Something went wrong, could not delete bruteforce entries for ' . $target . '.' . PHP_EOL;
        }
    }

    public function setDefaultRole()
    {
        $this->ConfigLoad->execute();
        if (empty($this->args[0]) || !is_numeric($this->args[0])) {
            $roles = $this->Role->find('list', array(
                'fields' => array('id', 'name')
            ));
            foreach ($roles as $k => $role) {
                $roles[$k] = $k . '. ' . $role;
            }
            $roles = implode(PHP_EOL, $roles);
            echo "Roles:\n" . $roles . $this->separator();
            echo 'Usage: ' . APP . 'cake ' . 'Admin setDefaultRole [role_id]' . PHP_EOL;
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

    public function change_authkey()
    {
        $this->ConfigLoad->execute();
        if (empty($this->args[0])) {
            echo 'MISP apikey command line tool.' . PHP_EOL . 'To assign a new random API key for a user: ' . APP . 'Console/cake change_authkey [email]' . PHP_EOL . 'To assign a fixed API key: ' . APP . 'Console/cake change_authkey [email] [authkey]' . PHP_EOL;
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

    public function getOptionParser()
    {
        $this->ConfigLoad->execute();
        $parser = parent::getOptionParser();
        $parser->addSubcommand('updateJSON', array(
            'help' => __('Update the JSON definitions of MISP.'),
            'parser' => array(
                'arguments' => array(
                    'update' => array('help' => __('Update the submodules before ingestion.'), 'short' => 'u', 'boolean' => 1)
                )
            )
        ));
        return $parser;
    }

    public function recoverSinceLastSuccessfulUpdate()
    {
        $this->ConfigLoad->execute();
        $this->loadModel('Log');
        $logs = $this->Log->find('all', array(
            'conditions' => array(
                'action' => 'update_database',
                'title LIKE ' => array(
                    'Successfuly executed the SQL query for %',
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
        $this->ConfigLoad->execute();
        echo 'Cleaning caches...' . PHP_EOL;
        $this->Server->cleanCacheFiles();
        echo '...caches lost in time, like tears in rain.' . PHP_EOL;
    }

    public function resetSyncAuthkeys()
    {
        $this->ConfigLoad->execute();
        if (empty($this->args[0])) {
            echo sprintf(
                __("MISP mass sync authkey reset command line tool.\n\nUsage: %sConsole/cake resetSyncAuthkeys [user_id]") . "\n\n",
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
        $this->ConfigLoad->execute();
        if (
            (empty($this->args[0]) || !is_numeric($this->args[0])) ||
            (empty($this->args[1]) || !is_numeric($this->args[1]))
        ) {
            echo 'Usage: ' . APP . '/cake ' . 'Admin purgeFeedEvents [user_id] [feed_id]' . PHP_EOL;
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
        $this->ConfigLoad->execute();
        $dbActualSchema = $this->Server->getActualDBSchema();
        $dbVersion = $this->AdminSetting->find('first', array(
            'conditions' => array('setting' => 'db_version')
        ));
        if (!empty($dbVersion) && !empty($dbActualSchema['schema'])) {
            $dbVersion = $dbVersion['AdminSetting']['value'];
            $data = array(
                'schema' => $dbActualSchema['schema'],
                'indexes' => $dbActualSchema['indexes'],
                'db_version' => $dbVersion
            );
            $file = new File(ROOT . DS . 'db_schema.json', true);
            $file->write(json_encode($data, JSON_PRETTY_PRINT) . "\n");
            $file->close();
            echo __("> Database schema dumped on disk") . PHP_EOL;
        } else {
            echo __("Something went wrong. Could not find the existing db version or fetch the current database schema.") . PHP_EOL;
        }
    }

    public function UserIP()
    {
        $this->ConfigLoad->execute();
        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['console_admin_tasks']['data']['Get IPs for user ID'] . PHP_EOL);
            die();
        }
        $user_id = trim($this->args[0]);
        $redis = $this->Server->setupRedis();
        $user = $this->User->find('first', array(
            'recursive' => -1,
            'conditions' => array('User.id' => $user_id)
        ));
        if (empty($user)) {
            echo PHP_EOL . 'Invalid user ID.';
            die();
        }
        $ips = $redis->smembers('misp:user_ip:' . $user_id);
        $ips = implode(PHP_EOL, $ips);
        echo sprintf(
            '%s==============================%sUser #%s: %s%s==============================%s%s%s==============================%s',
            PHP_EOL, PHP_EOL, $user['User']['id'], $user['User']['email'], PHP_EOL, PHP_EOL, $ips, PHP_EOL, PHP_EOL
        );
    }

    public function IPUser()
    {
        $this->ConfigLoad->execute();
        if (empty($this->args[0])) {
            die('Usage: ' . $this->Server->command_line_functions['console_admin_tasks']['data']['Get user ID for user IP'] . PHP_EOL);
            die();
        }
        $ip = trim($this->args[0]);
        $redis = $this->Server->setupRedis();
        $user_id = $redis->get('misp:ip_user:' . $ip);
        if (empty($user_id)) {
            echo PHP_EOL . 'No hits.' . PHP_EOL;
            die();
        }
        $user = $this->User->find('first', array(
            'recursive' => -1,
            'conditions' => array('User.id' => $user_id)
        ));

        echo sprintf(
            '%s==============================%sIP: %s%s==============================%sUser #%s: %s%s==============================%s',
            PHP_EOL, PHP_EOL, $ip, PHP_EOL, PHP_EOL, $user['User']['id'], $user['User']['email'], PHP_EOL, PHP_EOL
        );
    }

    public function scanAttachment()
    {
        $input = $this->args[0];
        $attributeId = isset($this->args[1]) ? $this->args[1] : null;
        $jobId = isset($this->args[2]) ? $this->args[2] : null;

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
}
