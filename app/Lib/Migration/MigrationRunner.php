<?php

/**
 * Executes a batch of schema-changing statements against the database, with
 * progress reporting, logging, error tolerance and maintenance-mode toggling.
 *
 * This is the executor that used to live at the tail of AppModel::updateDatabase().
 * It is shared: the legacy update path hands it the $sqlArray / $indexArray built
 * by AppModel's update switch, and the new migration system hands it rendered
 * statements. Nothing in here decides *what* to run - only how a run is carried
 * out and reported.
 *
 * It also owns the update state kept in admin_settings: the update_progress blob,
 * the update_locked timestamp and the update_fail_number counter. AppModel keeps
 * thin public delegators for those, so external callers are unaffected.
 *
 * The log titles written here are load-bearing: AdminShell::recoverSinceLastSuccessfulUpdate()
 * finds its restart point by LIKE-querying the logs table for
 * 'Successfully executed the SQL query for %'. They must not be reworded.
 */
class MigrationRunner
{
    /**
     * The model the run is carried out on. Supplies the datasource and the
     * update helpers that stay on AppModel.
     * @var Model
     */
    private $model;

    /** @var Log */
    private $Log;

    /** @var AdminSetting */
    private $AdminSetting;

    /** @var Server */
    private $Server;

    /**
     * Non-tolerated error messages from the most recent run(), in the order they
     * happened. The logs table and the progress blob both already carry them,
     * but neither is something a caller can read back cheaply - and the
     * migration ledger has to record *why* a migration failed, not just that it
     * did.
     *
     * @var array
     */
    private $errors = array();

    public function __construct(Model $model)
    {
        $this->model = $model;
    }

    /**
     * @return array The errors that stopped or degraded the most recent run.
     */
    public function lastErrors()
    {
        return $this->errors;
    }

    /**
     * Execute a batch of statements followed by a batch of deferred index additions.
     *
     * @param string $command The update being applied, used for progress and log titles.
     * @param array $sqlArray Statements to execute in order.
     * @param array $indexArray Deferred index additions as array($table, $field[, $length]).
     * @param bool $liveOff Take the instance out of live mode for the duration of the run.
     * @param bool $exitOnError Stop at the first non-tolerated error instead of continuing.
     * @param bool $clean Flush the model cache around the run.
     * @return bool False if the run stopped on an error, true otherwise.
     */
    public function run($command, array $sqlArray, array $indexArray, $liveOff = false, $exitOnError = false, $clean = true)
    {
        $this->Log = ClassRegistry::init('Log');
        $this->errors = array();

        // switch MISP instance live to false
        if ($liveOff) {
            $this->setLive(false);
        }
        $sql_update_count = count($sqlArray);
        $index_update_count = count($indexArray);
        $total_update_count = $sql_update_count + $index_update_count;
        $this->__setUpdateProgress(0, $total_update_count, $command);
        $str_index_array = array();
        foreach ($indexArray as $toIndex) {
            $str_index_array[] = __('Indexing %s -> %s', $toIndex[0], $toIndex[1]);
        }
        $this->__setUpdateCmdMessages(array_merge($sqlArray, $str_index_array));
        $flagStop = false;
        $errorCount = 0;

        // execute test before update. Exit if it fails
        if (isset(AppModel::ADVANCED_UPDATES_DESCRIPTION[$command]['preUpdate'])) {
            $function_name = AppModel::ADVANCED_UPDATES_DESCRIPTION[$command]['preUpdate'];
            try {
                $this->model->{$function_name}();
            } catch (Exception $e) {
                $this->__setPreUpdateTestState(false);
                $this->__setUpdateProgress(0, false);
                $this->__setUpdateResMessages(0, __('Issues executing the pre-update test `%s`. The returned error is: %s', $function_name, $e->getMessage()) . PHP_EOL);
                $this->__setUpdateError(0);
                $this->errors[] = __('Pre-update test `%s` failed: %s', $function_name, $e->getMessage());
                $errorCount++;
                $exitOnError = true;
                $flagStop = true;
            }
        }

        if (!$flagStop) {
            $this->__setPreUpdateTestState(true);
            foreach ($sqlArray as $i => $sql) {
                try {
                    $this->__setUpdateProgress($i, false);
                    $this->model->query($sql);
                    $this->Log->create();
                    $this->Log->saveOrFailSilently(array(
                        'org' => 'SYSTEM',
                        'model' => 'Server',
                        'model_id' => 0,
                        'email' => 'SYSTEM',
                        'action' => 'update_database',
                        'user_id' => 0,
                        'title' => __('Successfully executed the SQL query for ') . $command,
                        'change' => __('The executed SQL query was: %s', $sql),
                    ));
                    $this->__setUpdateResMessages($i, __('Successfully executed the SQL query for %s', $command));
                } catch (Exception $e) {
                    $errorMessage = $e->getMessage();
                    $this->Log->create();
                    $logMessage = array(
                        'org' => 'SYSTEM',
                        'model' => 'Server',
                        'model_id' => 0,
                        'email' => 'SYSTEM',
                        'action' => 'update_database',
                        'user_id' => 0,
                        'title' => __('Issues executing the SQL query for %s', $command),
                        'change' => __('The executed SQL query was: ') . $sql . PHP_EOL . __(' The returned error is: ') . $errorMessage
                    );
                    $this->__setUpdateResMessages($i, __('Issues executing the SQL query for `%s`. The returned error is: ' . PHP_EOL . '%s', $command, $errorMessage));
                    if (!$this->model->isAcceptedDatabaseError($errorMessage)) {
                        $this->__setUpdateError($i);
                        $this->errors[] = $errorMessage;
                        $errorCount++;
                        if ($exitOnError) {
                            $flagStop = true;
                            break;
                        }
                    } else {
                        $logMessage['change'] = $logMessage['change'] . PHP_EOL . __('However, as this error is allowed, the update went through.');
                    }
                    $this->Log->saveOrFailSilently($logMessage);
                }
            }
        }
        if (!$flagStop) {
            if (!empty($indexArray)) {
                if ($clean) {
                    $this->model->cleanCacheFiles();
                }
                foreach ($indexArray as $i => $iA) {
                    $this->__setUpdateProgress(count($sqlArray)+$i, false);
                    if (isset($iA[2])) {
                        $indexSuccess = $this->model->addIndex($iA[0], $iA[1], $iA[2]);
                    } else {
                        $indexSuccess = $this->model->addIndex($iA[0], $iA[1]);
                    }
                    if ($indexSuccess['success']) {
                        $this->__setUpdateResMessages(count($sqlArray)+$i, __('Successfully indexed %s -> %s', $iA[0], $iA[1]));
                    } else {
                        $this->__setUpdateResMessages(count($sqlArray)+$i, sprintf('%s %s %s %s',
                            __('Failed to add index'),
                            sprintf('%s -> %s', $iA[0], $iA[1]),
                            __('The returned error is:') . PHP_EOL,
                            $indexSuccess['errorMessage']
                        ));
                        $this->__setUpdateError(count($sqlArray)+$i);
                        $this->errors[] = $indexSuccess['errorMessage'];
                    }
                }
            }
            $this->__setUpdateProgress(count($sqlArray) + count($indexArray), false);
         }
        if ($clean) {
            $this->model->cleanCacheFiles();
        }
        if ($liveOff) {
            $this->setLive(true);
        }
        if (!$flagStop && $errorCount == 0) {
            $this->__postUpdate($command);
        }
        if ($flagStop && $errorCount > 0) {
            $this->Log->create();
            $this->Log->saveOrFailSilently(array(
                'org' => 'SYSTEM',
                'model' => 'Server',
                'model_id' => 0,
                'email' => 'SYSTEM',
                'action' => 'update_database',
                'user_id' => 0,
                'title' => __('Issues executing the SQL query for %s', $command),
                'change' => __('Database updates stopped as some errors occurred and the stop flag is enabled.')
            ));
            return false;
        }
        return true;
    }

    /**
     * Set if misp is live in redis or in config file as fallback
     * @param bool $isLive
     */
    private function setLive($isLive)
    {
        try {
            $redis = $this->model->setupRedisWithException();
            if ($isLive) {
                $redis->del('misp:live');
            } else {
                $redis->set('misp:live', '0');
            }
        } catch (Exception $e) {
            // pass
        }

        if (!isset($this->Server)) {
            $this->Server = ClassRegistry::init('Server');
        }
        $this->Server->serverSettingsSaveValue('MISP.live', $isLive);
    }

    /**
     * Check whether the adminSetting should be updated after the update.
     * @param string $command
     * @return void
     */
    private function __postUpdate($command)
    {
        if (isset(AppModel::ADVANCED_UPDATES_DESCRIPTION[$command]['record'])) {
            if (AppModel::ADVANCED_UPDATES_DESCRIPTION[$command]['record']) {
                $this->AdminSetting->changeSetting($command, 1);
            }
        }
    }

    private function __setUpdateProgress($current, $total=false, $toward_db_version=false)
    {
        $updateProgress = $this->getUpdateProgress();
        $updateProgress['current'] = $current;
        if ($total !== false) {
            $updateProgress['total'] = $total;
        } else {
            $now = new DateTime();
            $updateProgress['time']['started'][$current] = $now->format('Y-m-d H:i:s');
        }
        if ($toward_db_version !== false) {
            $updateProgress['toward_db_version'] = $toward_db_version;
        }
        $this->__saveUpdateProgress($updateProgress);
    }

    private function __setPreUpdateTestState($state)
    {
        $updateProgress = $this->getUpdateProgress();
        $updateProgress['preTestSuccess'] = $state;
        $this->__saveUpdateProgress($updateProgress);
    }

    private function __setUpdateError($index)
    {
        $updateProgress = $this->getUpdateProgress();
        $updateProgress['failed_num'][] = $index;
        $this->__saveUpdateProgress($updateProgress);
    }

    private function __getEmptyUpdateMessage()
    {
        return array(
            'commands' => array(),
            'results' => array(),
            'time' => array('started' => array(), 'elapsed' => array()),
            'current' => '',
            'total' => '',
            'failed_num' => array(),
            'toward_db_version' => ''
        );
    }

    public function resetUpdateProgress()
    {
        $updateProgress = $this->__getEmptyUpdateMessage();
        $this->__saveUpdateProgress($updateProgress);
    }

    private function __setUpdateCmdMessages($messages)
    {
        $updateProgress = $this->getUpdateProgress();
        $updateProgress['commands'] = $messages;
        $this->__saveUpdateProgress($updateProgress);
    }

    private function __setUpdateResMessages($index, $message)
    {
        $updateProgress = $this->getUpdateProgress();
        $updateProgress['results'][$index] = $message;
        $temp = new DateTime();
        $diff = $temp->diff(new DateTime($updateProgress['time']['started'][$index]));
        $updateProgress['time']['elapsed'][$index] = $diff->format('%H:%I:%S');
        $this->__saveUpdateProgress($updateProgress);
    }

    public function getUpdateProgress()
    {
        if (!isset($this->AdminSetting)) {
            $this->AdminSetting = ClassRegistry::init('AdminSetting');
        }
        $updateProgress = $this->AdminSetting->getSetting('update_progress');
        if ($updateProgress !== false) {
            $updateProgress = json_decode($updateProgress, true);
        } else {
            $updateProgress = $this->__getEmptyUpdateMessage();
        }
        foreach($updateProgress as $setting => $value) {
            if (!is_array($value)) {
                if (is_numeric($value)) {
                    $value = intval($value);
                }
            }
            $updateProgress[$setting] = $value;
        }
        return $updateProgress;
    }

    private function __saveUpdateProgress($updateProgress)
    {
        if (!isset($this->AdminSetting)) {
            $this->AdminSetting = ClassRegistry::init('AdminSetting');
        }
        $data = json_encode($updateProgress);
        $this->AdminSetting->changeSetting('update_progress', $data);
    }

    public function changeLockState($locked)
    {
        if (!isset($this->AdminSetting)) {
            $this->AdminSetting = ClassRegistry::init('AdminSetting');
        }
        $this->AdminSetting->changeSetting('update_locked', $locked);
    }

    private function getUpdateLockState()
    {
        if (!isset($this->AdminSetting)) {
            $this->AdminSetting = ClassRegistry::init('AdminSetting');
        }
        $locked = $this->AdminSetting->getSetting('update_locked');
        return is_null($locked) ? false : $locked;
    }

    public function getLockRemainingTime()
    {
        $lockState = $this->getUpdateLockState();
        if ($lockState !== false && $lockState !== '') {
            // if lock is old, still allows the update
            // This can be useful if the update process crashes
            $diffSec = time() - intval($lockState);
            if (Configure::read('MISP.updateTimeThreshold')) {
                $updateWaitThreshold = intval(Configure::read('MISP.updateTimeThreshold'));
            } else {
                $this->Server = ClassRegistry::init('Server');
                $updateWaitThreshold = intval($this->Server->serverSettings['MISP']['updateTimeThreshold']['value']);
            }
            $remainingTime = $updateWaitThreshold - $diffSec;
            return $remainingTime > 0 ? $remainingTime : 0;
        } else {
            return 0;
        }
    }

    public function isUpdateLocked()
    {
        $remainingTime = $this->getLockRemainingTime();
        $failThresholdReached = $this->UpdateFailNumberReached();
        return $remainingTime > 0 || $failThresholdReached;
    }

    private function getUpdateFailNumber()
    {
        $this->AdminSetting = ClassRegistry::init('AdminSetting');
        $updateFailNumber = $this->AdminSetting->getSetting('update_fail_number');
        return ($updateFailNumber !== false && $updateFailNumber !== '') ? $updateFailNumber : 0;
    }

    public function resetUpdateFailNumber()
    {
        $this->AdminSetting = ClassRegistry::init('AdminSetting');
        $this->AdminSetting->changeSetting('update_fail_number', 0);
    }

    public function increaseUpdateFailNumber()
    {
        $this->AdminSetting = ClassRegistry::init('AdminSetting');
        $updateFailNumber = $this->AdminSetting->getSetting('update_fail_number');
        $this->AdminSetting->changeSetting('update_fail_number', $updateFailNumber+1);
    }

    public function UpdateFailNumberReached()
    {
        return $this->getUpdateFailNumber() > 3;
    }
}
