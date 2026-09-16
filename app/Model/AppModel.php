<?php
/**
 * Application model for Cake.
 *
 * This file is application-wide model file. You can put all
 * application-wide model-related methods here.
 *
 * PHP 5
 *
 * CakePHP(tm) : Rapid Development Framework (http://cakephp.org)
 * Copyright 2005-2012, Cake Software Foundation, Inc. (http://cakefoundation.org)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright 2005-2012, Cake Software Foundation, Inc. (http://cakefoundation.org)
 * @link          http://cakephp.org CakePHP(tm) Project
 * @package       app.Model
 * @since         CakePHP(tm) v 0.2.9
 * @license       MIT License (http://www.opensource.org/licenses/mit-license.php)
 */

App::uses('Model', 'Model');
App::uses('LogableBehavior', 'Assets.models/behaviors');
App::uses('RandomTool', 'Tools');
App::uses('FileAccessTool', 'Tools');
App::uses('JsonTool', 'Tools');
App::uses('RedisTool', 'Tools');
App::uses('BetterCakeEventManager', 'Tools');
App::uses('Folder', 'Utility');
App::uses('MigrationRunner', 'Migration');
App::uses('MigrationManager', 'Migration');
App::uses('SchemaInspector', 'Migration');
App::uses('SqlDialect', 'Migration');
App::uses('LegacyMigrationsTrait', 'Migration');

class AppModel extends Model
{
    // The frozen historic update corpus - see app/Lib/Migration/LegacyMigrationsTrait.php
    use LegacyMigrationsTrait;

    /** @var PubSubTool */
    private static $loadedPubSubTool;

    /** @var KafkaPubTool */
    private $loadedKafkaPubTool;

    /** @var BackgroundJobsTool */
    private static $loadedBackgroundJobsTool;

    private $__profiler = array();

    /** @var AttachmentTool|null */
    private $attachmentTool;

    /** @var Workflow|null */
    private $Workflow;

    public $includeAnalystData;
    public $includeAnalystDataRecursive;

    private $dbiq = null;

    /** @var MigrationRunner|null */
    private $migrationRunner = null;

    /** @var MigrationManager|null */
    private $migrationManager = null;

    /** @var SchemaInspector|null */
    private $schemaInspector = null;

    /** @var SqlDialect|null */
    private $sqlDialect = null;

    // deprecated, use $db_changes
    // major -> minor -> hotfix -> requires_logout
    const OLD_DB_CHANGES = array(
        2 => array(
            4 => array(
                18 => false, 19 => false, 20 => false, 25 => false, 27 => false,
                32 => false, 33 => true, 38 => true, 39 => true, 40 => false,
                42 => false, 44 => false, 45 => false, 49 => true, 50 => false,
                51 => false, 52 => false, 55 => true, 56 => true, 57 => true,
                58 => false, 59 => false, 60 => false, 61 => false, 62 => false,
                63 => false, 64 => false, 65 => false, 66 => false, 67 => true,
                68 => false, 69 => false, 71 => false, 72 => false, 73 => false,
                75 => false, 77 => false, 78 => false, 79 => false, 80 => false,
                81 => false, 82 => false, 83 => false, 84 => false, 85 => false,
                86 => false, 87 => false
            )
        )
    );

	    const DB_CHANGES = array(
	        1 => false, 2 => false, 3 => false, 4 => true, 5 => false, 6 => false,
        7 => false, 8 => false, 9 => false, 10 => false, 11 => false, 12 => false,
        13 => false, 14 => false, 15 => false, 18 => false, 19 => false, 20 => false,
        21 => false, 22 => false, 23 => false, 24 => false, 25 => false, 26 => false,
        27 => false, 28 => false, 29 => false, 30 => false, 31 => false, 32 => false,
        33 => false, 34 => false, 35 => false, 36 => false, 37 => false, 38 => false,
        39 => false, 40 => false, 41 => false, 42 => false, 43 => false, 44 => false,
        45 => false, 46 => false, 47 => false, 48 => false, 49 => false, 50 => false,
        51 => false, 52 => false, 53 => false, 54 => false, 55 => false, 56 => false,
        57 => false, 58 => false, 59 => false, 60 => false, 61 => false, 62 => false,
        63 => true, 64 => false, 65 => false, 66 => false, 67 => false, 68 => false,
        69 => false, 70 => false, 71 => true, 72 => true, 73 => false, 74 => false,
        75 => false, 76 => true, 77 => false, 78 => false, 79 => false, 80 => false,
        81 => false, 82 => false, 83 => false, 84 => false, 85 => false, 86 => false,
        87 => false, 88 => false, 89 => false, 90 => false, 91 => false, 92 => false,
        93 => false, 94 => false, 95 => true, 96 => false, 97 => true, 98 => false,
        99 => false, 100 => false, 101 => false, 102 => false, 103 => false, 104 => false,
        105 => false, 106 => false, 107 => false, 108 => false, 109 => false, 110 => false,
        111 => false, 112 => false, 113 => true, 114 => false, 115 => false, 116 => false,
        117 => false, 118 => false, 119 => false, 120 => false, 121 => false, 122 => false,
        123 => false, 124 => false, 125 => false, 126 => false, 127 => false, 128 => false,
        129 => false, 130 => false, 131 => false, 132 => false, 133 => false, 134 => true,
        135 => false, 136 => true, 137 => false, 138 => false, 139 => false, 140 => false,
        141 => false, 142 => false, 143 => false, 144 => false, 145 => false, 146 => false,
        147 => false, 148 => false, 149 => false, 150 => false, 151 => false, 152 => false,
        153 => false, 154 => false, 157 => false, 158 => false, 159 => false
    );

    /**
     * The last number DB_CHANGES will ever carry.
     *
     * Everything after it is a migration under app/Lib/Migration/Migrations/,
     * recorded in the schema_migrations ledger rather than in db_version. The
     * corpus above is an archive of what instances in the wild have already run;
     * adding to it now would reintroduce the very bug the ledger removes, since
     * a number below an instance's high-water mark is silently never applied.
     *
     * findUpgrades() enforces this rather than trusting the comment.
     */
    const DB_CHANGES_FREEZE = 159;

    const ADVANCED_UPDATES_DESCRIPTION = array(
        'seenOnAttributeAndObject' => array(
            'title' => 'First seen/Last seen Attribute table',
            'description' => 'Update the Attribute table to support first_seen and last_seen feature, with a microsecond resolution.',
            'liveOff' => true, # should the instance be offline for users other than site_admin
            'recommendBackup' => true, # should the update recommend backup
            'exitOnError' => false, # should the update exit on error
            'requirements' => 'MySQL version must be >= 5.6', # message stating the requirements necessary for the update
            'record' => false, # should the update success be saved in the admin_table
            // 'preUpdate' => 'seenOnAttributeAndObjectPreUpdate', # Function to execute before the update. If it throws an error, it cancels the update
            'url' => '/servers/updateDatabase/seenOnAttributeAndObject/' # url pointing to the function performing the update
        ),
    );

    public function __construct($id = false, $table = null, $ds = null)
    {
        parent::__construct($id, $table, $ds);
        $this->findMethods['column'] = true;
        if (in_array('phar', stream_get_wrappers(), true)) {
            stream_wrapper_unregister('phar');
        }
    }

    public function dbiq()
    {
        if (!empty($this->dbiq)) {
            return $this->dbiq;
        }
        $db = ConnectionManager::getDataSource('default');
        if (!empty($db->dbiq)) {
            $this->dbiq = $db->dbiq;
            return $this->dbiq;
        }
        return '`';
    }

    public function isAcceptedDatabaseError($errorMessage)
    {
        if ($this->isMysql()) {
            $errorDuplicateColumn = 'SQLSTATE[42S21]: Column already exists: 1060 Duplicate column name';
            $errorDuplicateIndex = 'SQLSTATE[42000]: Syntax error or access violation: 1061 Duplicate key name';
            $errorDropIndex = "/SQLSTATE\[42000\]: Syntax error or access violation: 1091 Can't DROP '[\w]+'; check that column\/key exists/";
            $isAccepted = substr($errorMessage, 0, strlen($errorDuplicateColumn)) === $errorDuplicateColumn ||
                            substr($errorMessage, 0, strlen($errorDuplicateIndex)) === $errorDuplicateIndex ||
                            preg_match($errorDropIndex, $errorMessage) !== 0;
        } else {
            $errorDuplicateColumn = '/ERROR:  column "[\w]+" specified more than once/';
            $errorDuplicateIndex = '/ERROR: relation "[\w]+" already exists/';
            $errorDropIndex = '/ERROR: index "[\w]+" does not exist/';
            $isAccepted = preg_match($errorDuplicateColumn, $errorMessage) !== 0 ||
                            preg_match($errorDuplicateIndex, $errorMessage) !== 0 ||
                            preg_match($errorDropIndex, $errorMessage) !== 0;
        }
        return $isAccepted;
    }

    /**
     * Is this column indexed, with this uniqueness?
     *
     * Membership rather than position, matching what the SHOW INDEX query this
     * replaces asked: an index over (org_id, date) answers for either column.
     *
     * @param string $table
     * @param string $column_name
     * @param bool $is_unique Match unique indexes rather than non-unique ones.
     * @return bool
     */
    public function checkIndexExists($table, $column_name, $is_unique = false): bool
    {
        $inspector = $this->getSchemaInspector();
        return $inspector->indexNameForColumn($table, $column_name, !empty($is_unique)) !== null;
    }

    /**
     * @param string $table
     * @param string $index_name
     * @return bool
     */
    public function checkNamedIndexExists($table, $index_name): bool
    {
        return $this->getSchemaInspector()->hasNamedIndex($table, $index_name);
    }

    public function cleanCacheFiles()
    {
        Cache::clear();
        Cache::clear(false, '_cake_core_');
        Cache::clear(false, '_cake_model_');
        clearCache();

        $files = glob(CACHE . 'models' . DS . 'myapp*');
        $files = array_merge($files, glob(CACHE . 'persistent' . DS . 'myapp*'));
        foreach ($files as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }
        return true;
    }

    public function validateAuthkey($value)
    {
        if (empty($value['authkey'])) {
            return 'Empty authkey found. Make sure you set the 40 character long authkey.';
        }
        if (!preg_match('/[a-z0-9]{40}/i', $value['authkey'])) {
            return 'The authkey has to be exactly 40 characters long and consist of alphanumeric characters.';
        }
        return true;
    }

    // alternative to the build in notempty/notblank validation functions, compatible with cakephp <= 2.6 and cakephp and cakephp >= 2.7
    public function valueNotEmpty(array $value)
    {
        $field = array_key_first($value);
        $value = trim($value[$field]);
        if (!empty($value)) {
            return true;
        }
        return ucfirst($field) . ' cannot be empty.';
    }

    public function valueIsJsonOrString($value)
    {
        $value = current($value);
        if (is_array($value)) {
            if (!JsonTool::isValid($value)) {
                return __('Invalid JSON.');
            }
        }
        return true;
    }

    public function valueIsJson(array $value)
    {
        $value = current($value);
        if (!JsonTool::isValid($value)) {
            return __('Invalid JSON.');
        }
        return true;
    }

    public function valueIsID(array $value)
    {
        $field = array_key_first($value);
        if (!is_numeric($value[$field]) || $value[$field] < 0) {
            return 'Invalid ' . ucfirst($field) . ' ID';
        }
        return true;
    }

    public function stringNotEmpty(array $value)
    {
        $field = array_key_first($value);
        $value = trim($value[$field]);
        if (!isset($value) || ($value == false && $value !== "0")) {
            return ucfirst($field) . ' cannot be empty.';
        }
        return true;
    }

    // Try to create a table with a BIGINT(20)
    public function seenOnAttributeAndObjectPreUpdate()
    {
        $sqlArray[] = "CREATE TABLE IF NOT EXISTS testtable (
            `testfield` BIGINT(6) NULL DEFAULT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
        try {
            foreach($sqlArray as $i => $sql) {
                $this->query($sql);
            }
        } catch (Exception $e) {
            throw new Exception('Pre update test failed: ' . PHP_EOL . $sql . PHP_EOL . ' The returned error is: ' . $e->getMessage());
        }
        // clean up
        $sqlArray[] = "DROP TABLE testtable;";
        foreach($sqlArray as $i => $sql) {
            $this->query($sql);
        }
    }

    public function runUpdates($verbose = false, $useWorker = true, $processId = false, $avoidSilentFail = false)
    {
        $this->AdminSetting = ClassRegistry::init('AdminSetting');
        $this->Job = ClassRegistry::init('Job');

        $db = ConnectionManager::getDataSource('default');
        $tables = $db->listSources();
        $requiresLogout = false;
        // if we don't even have an admin table, time to create it.
        if (!in_array('admin_settings', $tables, true)) {
            $this->updateDatabase('adminTable');
            $requiresLogout = true;
        } else {
            $this->__runCleanDB();
            $db_version = $this->AdminSetting->find('all', [
                'conditions' => array('setting' => 'db_version'),
                'fields' => ['id', 'value'],
            ]);
            if (count($db_version) > 1) {
                // we ran into a bug where we have more than one db_version entry. This bug happened in some rare circumstances around 2.4.50-2.4.57
                foreach ($db_version as $k => $v) {
                    if ($k > 0) {
                        $this->AdminSetting->delete($v['AdminSetting']['id']);
                    }
                }
            }
            $db_version = $db_version[0];
            $updates = $this->findUpgrades($db_version['AdminSetting']['value']);
            if ($processId) {
                $job = $this->Job->find('first', array(
                    'conditions' => array('Job.id' => $processId)
                ));
            } else {
                $job = null;
            }
            if (!empty($updates)) {
                $this->Log = ClassRegistry::init('Log');
                $this->Server = ClassRegistry::init('Server');
                // Exit if updates are locked.
                // This is not as reliable as a real lock implementation
                // However, as all updates are re-playable, there is no harm if they
                // get played multiple time. The purpose of this lightweight lock
                // is only to limit the load.
                if ($this->isUpdateLocked()) { // prevent creation of useless workers
                    if ($avoidSilentFail) {
                        throw new Exception(__('Database updates are locked. Make sure that you have an update worker running. If you do, it might be related to an update\'s execution repeatedly failing or still being in progress.'));
                    }
                    $this->Log->create();
                    $this->Log->saveOrFailSilently(array(
                        'org' => 'SYSTEM',
                        'model' => 'Server',
                        'model_id' => 0,
                        'email' => 'SYSTEM',
                        'action' => 'update_db_worker',
                        'user_id' => 0,
                        'title' => __('Issues executing run_updates'),
                        'change' => __('Database updates are locked. Make sure that you have an update worker running. If you do, it might be related to an update\'s execution repeatedly failing or still being in progress.')
                    ));
                    if (!empty($job)) { // if multiple prio worker is enabled, want to mark them as done
                        $job['Job']['progress'] = 100;
                        $job['Job']['message'] = __('Update done');
                       $this->Job->save($job);
                    }
                    return true;
                }

                // restart this function by a worker
                if ($useWorker && Configure::read('MISP.background_jobs')) {
                    $workerIssueCount = 0;
                    $workerDiagnostic = $this->Server->workerDiagnostics($workerIssueCount);
                    if (isset($workerDiagnostic['update']['ok']) && $workerDiagnostic['update']['ok']) {
                        $workerType = 'update';
                    } else { // update worker not running, doing the update inline
                        return $this->runUpdates($verbose, false);
                    }

                    /** @var Job $job */
                    $job = ClassRegistry::init('Job');
                    $jobId = $job->createJob(
                            'SYSTEM',
                            Job::WORKER_UPDATE,
                            'run_updates',
                            'command: ' . implode(',', $updates),
                            'Updating.'
                        );

                    $this->getBackgroundJobsTool()->enqueue(
                        BackgroundJobsTool::UPDATE_QUEUE,
                        BackgroundJobsTool::CMD_ADMIN,
                        [
                            'runUpdates',
                            $jobId
                        ],
                        true,
                        $jobId
                    );

                    return true;
                }

                // See comment above for `isUpdateLocked()`
                // prevent continuation of job if worker was already spawned
                // (could happens if multiple prio workers are up)
                if ($this->isUpdateLocked()) {
                    $this->Log->create();
                    $this->Log->saveOrFailSilently(array(
                        'org' => 'SYSTEM',
                        'model' => 'Server',
                        'model_id' => 0,
                        'email' => 'SYSTEM',
                        'action' => 'update_db_worker',
                        'user_id' => 0,
                        'title' => __('Issues executing run_updates'),
                        'change' => __('Updates are locked. Stopping worker gracefully')
                    ));
                    if (!empty($job)) {
                        $job['Job']['progress'] = 100;
                        $job['Job']['message'] = __('Update done');
                        $this->Job->save($job);
                    }
                    return true;
                }
                $this->changeLockState(time());
                $this->__resetUpdateProgress();

                $update_done = 0;
                $haltedOn = null;
                $migrationManager = $this->getMigrationManager();
                foreach ($updates as $update => $temp) {
                    if ($verbose) {
                        echo str_pad('Executing ' . $update, 30, '.');
                    }
                    if (!empty($job)) {
                        $job['Job']['progress'] = floor($update_done / count($updates) * 100);
                        $job['Job']['message'] = __('Running update %s', $update);
                        $this->Job->save($job);
                    }
                    // findUpgrades() merged two key spaces into one map; this is
                    // where they part company again.
                    $isMigration = $migrationManager->has($update);
                    $dbUpdateSuccess = $isMigration ? $migrationManager->apply($update) : $this->updateMISP($update);
                    if ($temp) {
                        $requiresLogout = true;
                    }
                    $update_done++;
                    if ($dbUpdateSuccess) {
                        if (!$isMigration) {
                            $db_version['AdminSetting']['value'] = $update;
                            $this->AdminSetting->save($db_version);
                        }
                        // A migration has already recorded itself in the ledger,
                        // and db_version is frozen, so there is nothing to move.
                        $this->resetUpdateFailNumber();
                        if ($verbose) {
                            echo "\033[32mDone\033[0m" . PHP_EOL;
                        }
                    } else {
                        $haltedOn = $update;
                        $this->__increaseUpdateFailNumber();
                        $this->__logUpdateHalted($update, array_slice(array_keys($updates), $update_done));
                        if ($verbose) {
                            echo "\033[31mFailed\033[0m" . PHP_EOL;
                        }
                        // Updates are frequently interdependent - the canonical
                        // shape is add a column, migrate data into it, drop the
                        // old one - and running the successors of a failure has
                        // been destroying data quietly: the last of the three
                        // succeeds, advances db_version past the one that failed
                        // and resets the failure counter, so the instance ends up
                        // reporting itself fully updated with the data gone.
                        // Stop instead, and stay stopped until someone looks.
                        break;
                    }
                }
                if (!empty($job)) {
                    // A halted run is not a finished one. Saying "Update done"
                    // over a stalled instance is the same silence the ledger
                    // fields in the schema diagnostic exist to break.
                    $job['Job']['message'] = $haltedOn === null
                        ? __('Update done')
                        : __('Update halted: %s failed', $haltedOn);
                }
                $this->changeLockState(false);
                $this->__queueCleanDB();
            } else {
                if (!empty($job)) {
                    $job['Job']['message'] = __('Update done in another worker. Gracefully stopping.');
                }
            }
            // mark current worker as done, as well as queued workers than manages to pass the locks
            // (happens if user hit reload before first worker start its job)
            if (!empty($job)) {
                $job['Job']['progress'] = 100;
                $this->Job->save($job);
            }
        }
        if ($requiresLogout) {
            $this->refreshSessions();
        }
        return true;
    }

    /**
     * Record that a failed update stopped the run, and name what it blocked.
     *
     * Without this the halt is invisible: the failure itself is logged by
     * whichever path produced it, but nothing says that six further updates were
     * never attempted, which is the part an administrator needs in order to
     * understand why the instance has stopped moving.
     *
     * Deliberately not phrased like the titles
     * AdminShell::recoverSinceLastSuccessfulUpdate() LIKE-queries the logs table
     * for - those are load-bearing and this must not be mistaken for one.
     *
     * @param string|int $failed The update that stopped the run.
     * @param array $blocked The updates after it, none of which were attempted.
     * @return void
     */
    private function __logUpdateHalted($failed, array $blocked)
    {
        $this->Log = ClassRegistry::init('Log');
        $this->Log->create();
        $this->Log->saveOrFailSilently(array(
            'org' => 'SYSTEM',
            'model' => 'Server',
            'model_id' => 0,
            'email' => 'SYSTEM',
            'action' => 'update_database',
            'user_id' => 0,
            'title' => __('Database updates halted: %s failed', $failed),
            'change' => empty($blocked)
                ? __('Nothing was left to run after it.')
                : __('%s update(s) after it were not attempted and remain pending: %s', count($blocked), implode(', ', $blocked)),
        ));
    }

    /**
     * Update date_modified for all users, this will ensure that all users will refresh their session data.
     */
    private function refreshSessions()
    {
        $this->User = ClassRegistry::init('User');
        $this->User->updateAll(['date_modified' => time()]);
    }

    /**
     * @return MigrationRunner The shared executor for both the legacy update path and the migration system.
     */
    private function getMigrationRunner()
    {
        if ($this->migrationRunner === null) {
            $this->migrationRunner = new MigrationRunner($this);
        }
        return $this->migrationRunner;
    }

    /**
     * @return MigrationManager The new-style migrations and their ledger.
     */
    public function getMigrationManager()
    {
        if ($this->migrationManager === null) {
            $this->migrationManager = new MigrationManager($this);
        }
        return $this->migrationManager;
    }

    /**
     * The live schema, for anything that needs to know what the database
     * actually holds rather than what the models say it should.
     *
     * The migration system reaches it through MigrationManager; runtime code
     * asks here. Same class either way, on purpose - the two used to hand-write
     * their own information_schema and SHOW queries and could disagree about
     * whether an index existed.
     *
     * @return SchemaInspector
     */
    public function getSchemaInspector()
    {
        if ($this->schemaInspector === null) {
            $this->schemaInspector = new SchemaInspector($this->getDataSource());
        }
        return $this->schemaInspector;
    }

    /**
     * The engine's spelling for the constructs both engines can express.
     *
     * Anything that is only a spelling difference goes through here rather than
     * behind an isMysql() branch at the call site; anything structural belongs
     * in SchemaInspector, and anything that is a pure optimisation belongs in
     * checkDbSupport().
     *
     * @return SqlDialect
     */
    public function getSqlDialect()
    {
        if ($this->sqlDialect === null) {
            $this->sqlDialect = new SqlDialect($this->getDataSource());
        }
        return $this->sqlDialect;
    }

    /**
     * Bring this table's auto-increment counter back in line with its contents,
     * after rows were inserted with the key set by hand.
     *
     * Does nothing on MySQL, which tracks the high-water mark itself. The four
     * call sites that used to open-code this each carried their own engine
     * branch and their own hand-written setval() - one of them branching on the
     * configured datasource *name* rather than on the engine.
     *
     * @param string $column The auto-incrementing column.
     * @return void
     */
    public function resetAutoIncrement($column = 'id')
    {
        $sql = $this->getSqlDialect()->resetSequence($this->table, $column);
        if ($sql !== null) {
            $this->query($sql);
        }
    }

    /**
     * How much work runUpdates() has left to do, legacy and migrations together.
     *
     * Replaces the arithmetic the progress UI used to do for itself
     * (max(array_keys(DB_CHANGES)) - db_version), which counts version *numbers*
     * rather than updates - DB_CHANGES has gaps - and which after the freeze
     * would count nothing at all, since db_version can no longer move.
     *
     * @param string|int $db_version
     * @return int
     */
    public function countPendingUpdates($db_version)
    {
        return count($this->findUpgrades($db_version));
    }

    /**
     * The following are thin delegators to MigrationRunner, which owns the update
     * state held in admin_settings. They stay here because they are consumed from
     * outside the model layer (ServersController, Server::dbSchemaDiagnostic(),
     * AdminShell) and from runUpdates() below.
     */

    public function getUpdateProgress()
    {
        return $this->getMigrationRunner()->getUpdateProgress();
    }

    private function __resetUpdateProgress()
    {
        $this->getMigrationRunner()->resetUpdateProgress();
    }

    public function changeLockState($locked)
    {
        $this->getMigrationRunner()->changeLockState($locked);
    }

    public function getLockRemainingTime()
    {
        return $this->getMigrationRunner()->getLockRemainingTime();
    }

    public function isUpdateLocked()
    {
        return $this->getMigrationRunner()->isUpdateLocked();
    }

    public function resetUpdateFailNumber()
    {
        $this->getMigrationRunner()->resetUpdateFailNumber();
    }

    private function __increaseUpdateFailNumber()
    {
        $this->getMigrationRunner()->increaseUpdateFailNumber();
    }

    public function UpdateFailNumberReached()
    {
        return $this->getMigrationRunner()->UpdateFailNumberReached();
    }

    private function __queueCleanDB()
    {
        $this->AdminSetting = ClassRegistry::init('AdminSetting');
        $cleanDB = $this->AdminSetting->find('first', array('conditions' => array('setting' => 'clean_db')));
        if (empty($cleanDB)) {
            $this->AdminSetting->create();
            $cleanDB = array('AdminSetting' => array('setting' => 'clean_db', 'value' => 1));
        } else {
            $cleanDB['AdminSetting']['value'] = 1;
        }
        $this->AdminSetting->save($cleanDB);
    }

    private function __runCleanDB()
    {
        $cleanDB = $this->AdminSetting->getSetting('clean_db');
        if ($cleanDB === false || $cleanDB == 1) {
            $this->cleanCacheFiles();
            $this->AdminSetting->changeSetting('clean_db', 0);
        }
    }

    /**
     * Everything runUpdates() still has to apply, in the order it must apply it.
     *
     * Two sources, one map. The legacy corpus is frozen at DB_CHANGES_FREEZE and
     * keyed by an integer high-water mark; migrations are keyed by their ledger
     * ID and are pending purely because the ledger has no applied row for them.
     * The union is safe because the two key spaces cannot collide - a legacy key
     * is an int or a '2.4.x' string, and a migration ID is a timestamp and a
     * slug, which PHP will not cast to an integer key - and the union operator
     * preserves left-hand order, so all pending legacy updates come first,
     * followed by the migrations in ID order, with no sorting step.
     *
     * @param string $db_version
     * @return array command => requiresLogout
     * @throws Exception If the frozen corpus has grown.
     */
    protected function findUpgrades($db_version)
    {
        $this->assertLegacyCorpusFrozen();
        $updates = array();
        if (strpos($db_version, '.')) {
            $version = explode('.', $db_version);
            foreach (self::OLD_DB_CHANGES as $major => $rest) {
                if ($major < $version[0]) {
                    continue;
                } elseif ($major == $version[0]) {
                    foreach ($rest as $minor => $hotfixes) {
                        if ($minor < $version[1]) {
                            continue;
                        } elseif ($minor == $version[1]) {
                            foreach ($hotfixes as $hotfix => $requiresLogout) {
                                if ($hotfix > $version[2]) {
                                    $updates[$major . '.' . $minor . '.' . $hotfix] = $requiresLogout;
                                }
                            }
                        } else {
                            foreach ($hotfixes as $hotfix => $requiresLogout) {
                                $updates[$major . '.' . $minor . '.' . $hotfix] = $requiresLogout;
                            }
                        }
                    }
                }
            }
            $db_version = 0;
        }
        foreach (self::DB_CHANGES as $db_change => $requiresLogout) {
            if ($db_version < $db_change) {
                $updates[$db_change] = $requiresLogout;
            }
        }
        return $updates + $this->getMigrationManager()->pending();
    }

    /**
     * Nothing may be added to DB_CHANGES after the freeze.
     *
     * A case numbered above it would be applied by instances below that number
     * and silently skipped by every instance already past it - which is exactly
     * the failure the ledger was built to remove, reappearing in the code that
     * removed it. Checked here rather than left to a comment, because a process
     * rule alone is what produced the original bug.
     *
     * @return void
     * @throws Exception
     */
    private function assertLegacyCorpusFrozen()
    {
        $highest = max(array_keys(self::DB_CHANGES));
        if ($highest > self::DB_CHANGES_FREEZE) {
            throw new Exception(sprintf(
                'DB_CHANGES is frozen at %d but carries %d. New schema changes belong in app/Lib/Migration/Migrations/ as migration classes, not in the legacy corpus - a case added above the freeze is applied by some instances and silently skipped by others.',
                self::DB_CHANGES_FREEZE,
                $highest
            ));
        }
    }

    public function checkFilename($filename)
    {
        return preg_match('@^([a-z0-9_.]+[a-z0-9_.\- ]*[a-z0-9_.\-]|[a-z0-9_.])+$@i', $filename);
    }

    /**
     * Similar method as `setupRedis`, but this method throw exception if Redis cannot be reached.
     * @return Redis
     * @throws Exception
     * @deprecated
     */
    public function setupRedisWithException()
    {
        return RedisTool::init();
    }

    /**
     * Method for backward compatibility.
     * @deprecated
     * @see AppModel::setupRedisWithException
     * @return bool|Redis
     */
    public function setupRedis()
    {
        try {
            return RedisTool::init();
        } catch (Exception $e) {
            return false;
        }
    }

    public function getKafkaPubTool()
    {
        if (!$this->loadedKafkaPubTool) {
            App::uses('KafkaPubTool', 'Tools');
            $kafkaPubTool = new KafkaPubTool();
            $rdkafkaIni = Configure::read('Plugin.Kafka_rdkafka_config');
            $rdkafkaIni = mb_ereg_replace("/\:\/\//", '', $rdkafkaIni);
            $kafkaConf = array();
            if (!empty($rdkafkaIni)) {
                $kafkaConf = parse_ini_file($rdkafkaIni);
            }
            $brokers = Configure::read('Plugin.Kafka_brokers');
            $kafkaPubTool->initTool($brokers, $kafkaConf);
            $this->loadedKafkaPubTool = $kafkaPubTool;
        }
        return $this->loadedKafkaPubTool;
    }

    public function publishKafkaNotification($topicName, $data, $action = false)
    {
        $kafkaTopic = $this->kafkaTopic($topicName);
        if ($kafkaTopic) {
            $this->getKafkaPubTool()->publishJson($kafkaTopic, $data, $action);
        }
    }

    /**
     * @return PubSubTool
     */
    public function getPubSubTool()
    {
        if (!self::$loadedPubSubTool) {
            App::uses('PubSubTool', 'Tools');
            $pubSubTool = new PubSubTool();
            $pubSubTool->initTool();
            self::$loadedPubSubTool = $pubSubTool;
        }
        return self::$loadedPubSubTool;
    }

    /**
     * @return BackgroundJobsTool
     */
    public function getBackgroundJobsTool(): BackgroundJobsTool
    {
        if (!self::$loadedBackgroundJobsTool) {
            App::uses('BackgroundJobsTool', 'Tools');

            // TODO: remove after CakeResque is deprecated
            $settings = ['enabled' => false];
            if (Configure::read('SimpleBackgroundJobs.enabled')) {
                $settings = Configure::read('SimpleBackgroundJobs');
            }

            $backgroundJobsTool = new BackgroundJobsTool($settings);
            self::$loadedBackgroundJobsTool = $backgroundJobsTool;
        }
        return self::$loadedBackgroundJobsTool;
    }

    /**
     * Generate a generic subquery - options needs to include conditions
     *
     * @param AppModel $model
     * @param array $options
     * @param string $lookupKey
     * @param bool $negation
     * @return string[]
     */
    /**
     * A correlated subquery reading one column of the row another table's
     * alias points at - `(SELECT t.column FROM t WHERE t.id = Alias.foreignKey)`
     * - spelled for this connection.
     *
     * Every identifier is quoted through the driver and the table is
     * schema-qualified when the connection names a schema, because the driver
     * does not reach inside a hand-written condition string to do either.
     * Use the result as a raw condition string, `<subquery> = 3` or
     * `<subquery> IN (1, 2)`, never as an array key with a value: CakePHP
     * splits such a key at its last space to find an operator, and the tail
     * of the subquery is then appended unquoted.
     *
     * @param string $table
     * @param string $column
     * @param string $alias The model alias in the enclosing query.
     * @param string $foreignKey Its column holding the looked-up row's id.
     * @return string
     */
    protected function correlatedLookup($table, $column, $alias, $foreignKey)
    {
        $db = $this->getDataSource();
        $qualified = empty($db->config['schema'])
            ? $db->name($table)
            : $db->name($db->config['schema']) . '.' . $db->name($table);
        return sprintf(
            '(SELECT %s.%s FROM %s WHERE %s.%s = %s.%s)',
            $qualified,
            $db->name($column),
            $qualified,
            $qualified,
            $db->name('id'),
            $db->name($alias),
            $db->name($foreignKey)
        );
    }

    protected function subQueryGenerator(AppModel $model, array $options, $lookupKey, $negation = false)
    {
        $defaults = array(
            'fields' => array('*'),
            'table' => $model->table,
            'alias' => $model->alias,
            'limit' => null,
            'offset' => null,
            'joins' => array(),
            'conditions' => array(),
            'group' => false,
            'recursive' => -1
        );
        $params = array();
        foreach ($defaults as $key => $defaultValue) {
            if (isset($options[$key])) {
                $params[$key] = $options[$key];
            } else {
                $params[$key] = $defaultValue;
            }
        }
        $db = $model->getDataSource();
        $subQuery = $db->buildStatement($params, $model);
        if ($negation) {
            $subQuery = $lookupKey . ' NOT IN (' . $subQuery . ') ';
        } else {
            $subQuery = $lookupKey . ' IN (' . $subQuery . ') ';
        }
        return [$subQuery];
    }

    /**
     * Returns estimated number of table rows
     *
     * The estimate is now taken for *this* connection's database. The query
     * this replaced filtered on the table name alone and took the first row, so
     * on a server hosting more than one MISP it answered with whichever
     * same-named table information_schema happened to list first.
     *
     * @return int
     */
    public function tableRows()
    {
        return $this->getSchemaInspector()->tableRowEstimate($this->table);
    }

    // start a benchmark run for the given bench name
    public function benchmarkInit($name = 'default')
    {
        $this->__profiler[$name]['start'] = microtime(true);
        if (empty($this->__profiler[$name]['memory_start'])) {
            $this->__profiler[$name]['memory_start'] = memory_get_usage();
        }
        return true;
    }

    // calculate the duration from the init time to the current point in execution. Aggregate flagged executions will increment the duration instead of just setting it
    public function benchmark($name = 'default', $aggregate = false, $memory_chart = false)
    {
        if (!empty($this->__profiler[$name]['start'])) {
            if ($aggregate) {
                if (!isset($this->__profiler[$name]['duration'])) {
                    $this->__profiler[$name]['duration'] = 0;
                }
                if (!isset($this->__profiler[$name]['executions'])) {
                    $this->__profiler[$name]['executions'] = 0;
                }
                $this->__profiler[$name]['duration'] += microtime(true) - $this->__profiler[$name]['start'];
                $this->__profiler[$name]['executions']++;
                $currentUsage = memory_get_usage();
                if ($memory_chart) {
                    $this->__profiler[$name]['memory_chart'][] = $currentUsage - $this->__profiler[$name]['memory_start'];
                }
                if (
                    empty($this->__profiler[$name]['memory_peak']) ||
                    $this->__profiler[$name]['memory_peak'] < ($currentUsage - $this->__profiler[$name]['memory_start'])
                ) {
                    $this->__profiler[$name]['memory_peak'] = $currentUsage - $this->__profiler[$name]['memory_start'];
                }
            } else {
                $this->__profiler[$name]['memory_peak'] = memory_get_usage() - $this->__profiler[$name]['memory_start'];
                $this->__profiler[$name]['duration'] = microtime(true) - $this->__profiler[$name]['start'];
            }
        }
        return true;
    }

    // return the results of the benchmark(s). If no name is set all benchmark results are returned in an array.
    public function benchmarkResult($name = false)
    {
        if ($name) {
            return array($name => $this->__profiler[$name]['duration']);
        } else {
            $results = array();
            foreach ($this->__profiler as $name => $benchmark) {
                if (!empty($benchmark['duration'])) {
                    $results[$name] = $benchmark;
                    unset($results[$name]['start']);
                    unset($results[$name]['memory_start']);
                }
            }
            return $results;
        }
    }

    public function benchmarkCustomAdd($valueToAdd = 0, $name = 'default', $customName = 'custom')
    {
        if (empty($this->__profiler[$name]['custom'][$customName])) {
            $this->__profiler[$name]['custom'][$customName] = 0;
        }
        $this->__profiler[$name]['custom'][$customName] += $valueToAdd;
    }

    public function setupHttpSocket($server, $HttpSocket = null, $timeout = false, $model = null)
    {
        if (empty($HttpSocket)) {
            App::uses('SyncTool', 'Tools');
            $syncTool = new SyncTool();

            if ($model !== null) {
                $HttpSocket = $syncTool->setupHttpSocket($server, $timeout, $model);
            } else {
                $HttpSocket = $syncTool->setupHttpSocket($server, $timeout);
            }
        }
        return $HttpSocket;
    }
    
    /**
     * @param array $server
     * @param string $model
     * @return array[]
     * @throws JsonException
     */
    public function setupSyncRequest(array $server, $model = 'Server')
    {
        $version = implode('.', $this->checkMISPVersion());
        $commit = $this->checkMIPSCommit();

        $authkey = $server[$model]['authkey'];
        App::uses('EncryptedValue', 'Tools');
        if (EncryptedValue::isEncrypted($authkey)) {
            $authkey = (string)new EncryptedValue($authkey);
        }

        return array(
            'header' => array(
                'Authorization' => $authkey,
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'User-Agent' => 'MISP ' . $version . (empty($commit) ? '' : ' - #' . $commit),
            )
        );
    }

    /**
     * Returns MISP version from VERSION.json file as array with major, minor and hotfix keys.
     *
     * @return array
     * @throws Exception
     */
    public function checkMISPVersion()
    {
        static $versionArray;
        if ($versionArray === null) {
            $versionArray = FileAccessTool::readJsonFromFile(ROOT . DS . 'VERSION.json', true);
        }
        return $versionArray;
    }

    /**
     * Returns MISP commit hash.
     *
     * @return false|string
     */
    public function checkMIPSCommit()
    {
        static $commit;
        if ($commit === null) {
            App::uses('GitTool', 'Tools');
            try {
                $commit = GitTool::currentCommit(ROOT);
            } catch (Exception $e) {
                $this->logException('Could not get current git commit', $e, LOG_NOTICE);
                $commit = false;
            }
        }
        return $commit;
    }

    // take filters in the {"OR" => [foo], "NOT" => [bar]} format along with conditions and set the conditions
    public function generic_add_filter($conditions, &$filter, $keys, $conditional_for_filter = null)
    {
        $operator_composition = array(
            'NOT' => 'AND',
            'OR' => 'OR',
            'AND' => 'AND'
        );
        if (!is_array($keys)) {
            $keys = array($keys);
        }
        if (!isset($filter['OR']) && !isset($filter['AND']) && !isset($filter['NOT'])) {
            return $conditions;
        }
        foreach ($filter as $operator => $filters) {
            $temp = array();
            if (!is_array($filters)) {
                $filters = array($filters);
            }
            foreach ($filters as $f) {
                if ($f === -1) {
                    foreach ($keys as $key) {
                        if ($this->checkParam($key)) {
                            $temp['OR'][$key][] = -1;
                        }
                    }
                    continue;
                }
                // split the filter params into two lists, one for substring searches one for exact ones
                if (is_string($f) && (str_ends_with($f, '%') || str_starts_with($f, '%'))) {
                    foreach ($keys as $key) {
                        if ($this->checkParam($key)) {
                            if ($operator === 'NOT') {
                                $temp[] = array($key . ' NOT LIKE' => $f);
                            } else {
                                $temp[] = array($key . ' LIKE' => $f);
                                $temp[] = array($key => $f);
                            }
                        }
                    }
                } else {
                    foreach ($keys as $key) {
                        if ($this->checkParam($key)) {
                            if ($operator === 'NOT') {
                                $temp[$key . ' !='][] = $f;
                            } else {
                                $temp['OR'][$key . ' IN'][] = $f;
                            }
                        }
                    }
                }
            }
            if (!empty($conditional_for_filter)) {
                $conditions['AND'][] = [
                    'OR' => [
                        $conditional_for_filter,
                        [
                            $operator_composition[$operator] => $temp
                        ]
                    ]
                ];
            } else {
                $conditions['AND'][] = [
                    $operator_composition[$operator] => $temp
                ];
            }
            if ($operator !== 'NOT') {
                unset($filter[$operator]);
            }
        }
        return $conditions;
    }

    /*
     * Get filters in one of the following formats:
     * [foo, bar]
     * ["OR" => [foo, bar], "NOT" => [baz]]
     * "foo"
     * "foo&&bar&&!baz"
     * and convert it into the same format ["OR" => [foo, bar], "NOT" => [baz]]
     */
    public function convert_filters($filter)
    {
        if (!is_array($filter)) {
            $temp = explode('&&', $filter);
            $filter = array();
            foreach ($temp as $f) {
                $f = strval($f);
                if ($f !== '') {
                    if ($f[0] === '!') {
                        $filter['NOT'][] = substr($f, 1);
                    } else {
                        $filter['OR'][] = $f;
                    }
                }
            }
            return $filter;
        }
        if (!isset($filter['OR']) && !isset($filter['NOT']) && !isset($filter['AND'])) {
            $temp = array();
            foreach ($filter as $param) {
                $paramString = strval($param);
                if (!empty($paramString) && !is_int($param)) {
                    if ($paramString[0] === '!') {
                        $temp['NOT'][] = substr($paramString, 1);
                    } else {
                        $temp['OR'][] = $paramString;
                    }
                } else if (isset($param)) {
                    $temp['OR'][] = $param;
                }
            }
            $filter = $temp;
        }
        return $filter;
    }

    protected function convert_to_memory_limit_to_mb($val)
    {
        $val = trim($val);
        if ($val == -1) {
            // default to 8GB if no limit is set
            return 8 * 1024;
        }
        $unit = $val[strlen($val)-1];
        if (is_numeric($unit)) {
            $unit = 'b';
        } else {
            $val = intval($val);
        }
        $unit = strtolower($unit);
        switch ($unit) {
            case 'g':
                $val *= 1024;
                // no break
            case 'm':
                $val *= 1024;
                // no break
            case 'k':
                $val *= 1024;
        }
        return $val / (1024 * 1024);
    }

    public function generateRandomFileName()
    {
        return RandomTool::random_str(false, 12);
    }

    /**
     * @param string|int $delta
     * @return int Timestamp
     */
    public function resolveTimeDelta($delta)
    {
        if (is_numeric($delta)) {
            return (int)$delta;
        }

        $multiplierArray = ['d' => 86400, 'h' => 3600, 'm' => 60, 's' => 1];
        $lastChar = strtolower(substr($delta, -1));
        if (!is_numeric($lastChar) && isset($multiplierArray[$lastChar])) {
            $multiplier = $multiplierArray[$lastChar];
            $timeDelta = substr($delta, 0, -1);
            if (!is_numeric($timeDelta)) {
                $this->log('Invalid time filter format ' . $delta, LOG_NOTICE);
                return time() + 1;
            }
            return time() - ($timeDelta * $multiplier);
        }

        $time = strtotime($delta);
        if ($time !== false) {
            return $time;
        }

        $this->log('Invalid time filter format ' . $delta, LOG_NOTICE);
        return time() + 1;
    }

    protected function _findList($state, $query, $results = [])
    {
        if ($state === 'before') {
            return parent::_findList($state, $query, $results);
        }

        if (empty($results)) {
            return [];
        }

        if ($query['list']['groupPath'] === null) {
            $keyPath = explode('.', $query['list']['keyPath']);
            $valuePath = explode('.', $query['list']['valuePath']);
            if ($keyPath[1] === $valuePath[1]) { // same model
                $results = array_column($results, $keyPath[1]);
                return array_column($results, $valuePath[2], $keyPath[2]);
            }
        }

        return parent::_findList($state, $query, $results);
    }

    /**
     * Find method that allows to fetch just one column from database.
     * @param $state
     * @param $query
     * @param array $results
     * @return array
     * @throws InvalidArgumentException
     */
    protected function _findColumn($state, $query, $results = array())
    {
        if ($state === 'before') {
            if (isset($query['fields']) && is_array($query['fields']) && count($query['fields']) === 1) {
                if (!str_contains($query['fields'][0], '.')) {
                    $query['fields'][0] = $this->alias . '.' . $query['fields'][0];
                }

                $query['column'] = $query['fields'][0];
                if (isset($query['unique']) && $query['unique']) {
                    $query['fields'] = array("DISTINCT {$query['fields'][0]}");
                } else {
                    $query['fields'] = array($query['fields'][0]);
                }
            } else if (!isset($query['fields'])) {
                throw new InvalidArgumentException("This method requires `fields` option defined.");
            } else {
                throw new InvalidArgumentException("Invalid number of column, expected one, " . count($query['fields']) . " given");
            }

            if (!isset($query['recursive'])) {
                $query['recursive'] = -1;
            }

            return $query;
        }

        // Faster version of `Hash::extract`
        foreach (explode('.', $query['column']) as $part) {
            $results = array_column($results, $part);
        }
        return $results;
    }

    /**
     * @param string $field
     * @param AppModel $model
     * @param array $conditions
     */
    public function addCountField($field, AppModel $model, array $conditions)
    {
        $db = $this->getDataSource();
        $subQuery = $db->buildStatement(
            array(
                'fields'     => ['COUNT(*)'],
                'table'      => $db->fullTableName($model),
                'alias'      => $model->alias,
                'conditions' => $conditions,
            ),
            $model
        );
        $this->virtualFields[$field] = $subQuery;
    }

    /**
     * Log exception with backtrace and with nested exceptions.
     *
     * @param string $message
     * @param Exception $exception
     * @param int $type
     * @return bool
     */
    protected function logException($message, Exception $exception, $type = LOG_ERR)
    {
        // If Sentry is installed, send exception to Sentry
        if (function_exists('\Sentry\captureException') && $type <= LOG_ERR) {
            \Sentry\captureException(new Exception($message, $type, $exception));
        }

        do {
            $message .= sprintf("\n[%s] %s", get_class($exception), $exception->getMessage());
            $message .= "\nStack Trace:\n" . $exception->getTraceAsString();
            $exception = $exception->getPrevious();
        } while ($exception !== null);

        return $this->log($message, $type);
    }

    /**
     * Decodes JSON string and throws exception if string is not valid JSON or if is not array.
     *
     * @param string $json
     * @return array
     * @throws JsonException
     * @throws UnexpectedValueException
     * @deprecated
     */
    protected function jsonDecode($json)
    {
        return JsonTool::decodeArray($json);
    }

    /**
     * Faster version of default `hasAny` method
     * @param array|null $conditions
     * @return bool
     */
    public function hasAny($conditions = null)
    {
        return (bool)$this->find('first', [
            'fields' => [$this->alias . '.' . $this->primaryKey],
            'conditions' => $conditions,
            'recursive' => -1,
            'callbacks' => false,
            'order' => [], // disable order
        ]);
    }

    /**
     * Faster version of original `isUnique` method
     * {@inheritDoc}
     */
    public function isUnique($fields, $or = true)
    {
        if (is_array($or)) {
            $isRule = (
                array_key_exists('rule', $or) &&
                array_key_exists('required', $or) &&
                array_key_exists('message', $or)
            );
            if (!$isRule) {
                $args = func_get_args();
                $fields = $args[1];
                $or = $args[2] ?? true;
            }
        }
        if (!is_array($fields)) {
            $fields = func_get_args();
            $fieldCount = count($fields) - 1;
            if (is_bool($fields[$fieldCount])) {
                $or = $fields[$fieldCount];
                unset($fields[$fieldCount]);
            }
        }

        foreach ($fields as $field => $value) {
            if (is_numeric($field)) {
                unset($fields[$field]);

                $field = $value;
                $value = null;
                if (isset($this->data[$this->alias][$field])) {
                    $value = $this->data[$this->alias][$field];
                }
            }

            if (!str_contains($field, '.')) {
                unset($fields[$field]);
                $fields[$this->alias . '.' . $field] = $value;
            }
        }

        if ($or) {
            $fields = array('or' => $fields);
        }

        if (!empty($this->id)) {
            $fields[$this->alias . '.' . $this->primaryKey . ' !='] = $this->id;
        }

        return !$this->hasAny($fields);
    }

    /**
     * Faster version of original `exists` method
     * {@inheritDoc}
     */
    public function exists($id = null)
    {
        if ($id === null) {
            $id = $this->getID();
        }

        if ($id === false || $this->useTable === false) {
            return false;
        }

        return $this->hasAny([$this->alias . '.' . $this->primaryKey => $id]);
    }

    /**
     * @param int $value Timestamp in microseconds
     * @return string
     */
    protected function microTimestampToIso($value)
    {
        $sec = (int)($value / 1000000);
        $micro = $value % 1000000;
        $micro = str_pad($micro, 6, "0", STR_PAD_LEFT);
        return DateTime::createFromFormat('U.u', "$sec.$micro")->format('Y-m-d\TH:i:s.uP');
    }

    /**
     * @return AttachmentTool
     */
    protected function loadAttachmentTool()
    {
        if ($this->attachmentTool === null) {
            $this->attachmentTool = new AttachmentTool();
        }

        return $this->attachmentTool;
    }

    /**
     * @return AttachmentScan
     */
    protected function loadAttachmentScan()
    {
        if ($this->AttachmentScan === null) {
            $this->AttachmentScan = ClassRegistry::init('AttachmentScan');
        }

        return $this->AttachmentScan;
    }

    /**
     * @return Log
     */
    protected function loadLog()
    {
        if (!isset($this->Log)) {
            $this->Log = ClassRegistry::init('Log');
        }
        return $this->Log;
    }

    /**
     * @param string $name
     * @return string|null Null when Kafka is not enabled, topic is not enabled or topic is not defined
     */
    protected function kafkaTopic($name)
    {
        static $kafkaEnabled;
        if ($kafkaEnabled === null) {
            $kafkaEnabled = (bool)Configure::read('Plugin.Kafka_enable');
        }
        if ($kafkaEnabled) {
            if (!Configure::read("Plugin.Kafka_{$name}_notifications_enable")) {
                return null;
            }
            return Configure::read("Plugin.Kafka_{$name}_notifications_topic") ?: null;
        }
        return null;
    }

    /**
     * @param string $name
     * @return bool
     */
    protected function pubToZmq($name)
    {
        static $zmqEnabled;
        if ($zmqEnabled === null) {
            $zmqEnabled = (bool)Configure::read('Plugin.ZeroMQ_enable');
        }
        if ($zmqEnabled) {
            return Configure::read("Plugin.ZeroMQ_{$name}_notifications_enable");
        }
        return false;
    }

    /**
     * @return bool Returns true if database is MySQL/Mariadb, false for PostgreSQL
     */
    protected function isMysql()
    {
        $dataSource = ConnectionManager::getDataSource('default');
        return $dataSource instanceof Mysql;
    }

    /**
     * executeTrigger
     *
     * @param string $trigger_id
     * @param array $data Data to be passed to the workflow
     * @param array $blockingErrors Errors will be appended if any
     * @param array $logging If the execution failure should be logged
     * @return boolean If the execution for the blocking path was a success
     */
    protected function executeTrigger($trigger_id, array $data=[], array &$blockingErrors=[], array $logging=[]): bool
    {
        if ($this->isTriggerCallable($trigger_id)) {
           $success = $this->Workflow->executeWorkflowForTriggerRouter($trigger_id, $data, $blockingErrors, $logging);
           if (!empty($logging) && empty($success)) {
                $logging['message'] = !empty($logging['message']) ? $logging['message'] : __('Error while executing workflow.');
                $errorMessage = implode(', ', $blockingErrors);
                $this->loadLog()->createLogEntry('SYSTEM', $logging['action'], $logging['model'], $logging['id'], $logging['message'], __('Returned message: %s', $errorMessage));
           }
           return $success;
        }
        return true;
    }

    protected function isTriggerCallable($trigger_id): bool
    {
        static $workflowEnabled;
        if ($workflowEnabled === null) {
            $workflowEnabled = (bool)Configure::read('Plugin.Workflow_enable');
        }

        if (!$workflowEnabled) {
            return false;
        }

        if ($this->Workflow === null) {
            $this->Workflow = ClassRegistry::init('Workflow');
        }
        return $this->Workflow->checkTriggerEnabled($trigger_id) &&
            $this->Workflow->checkTriggerListenedTo($trigger_id);
    }

    /**
     * Use different CakeEventManager to fix memory leak
     * @return CakeEventManager
     */
    public function getEventManager()
    {
        if (empty($this->_eventManager)) {
            $this->_eventManager = new BetterCakeEventManager();
            $this->_eventManager->attach($this->Behaviors);
            $this->_eventManager->attach($this);
        }
        return $this->_eventManager;
    }

    public function removeDuplicateCorrelationEntries($table_name = 'default_correlations')
    {
        // If there are duplicate entries, the query creating the `unique_correlation` index will result in an integrity constraint violation.
        // The query below cleans up potential duplicates before creating the constraint.
        return $this->query("
            DELETE FROM `$table_name` WHERE id in (
                SELECT m_id FROM (
                    SELECT MAX(corr_a.id) as m_id, CONCAT(corr_a.attribute_id, \" - \", corr_a.1_attribute_id, \" - \", corr_a.value_id) as uniq FROM `$table_name` corr_a
                    INNER JOIN `$table_name` corr_b on corr_a.attribute_id = corr_b.attribute_id
                    WHERE
                        corr_a.attribute_id = corr_b.attribute_id AND
                        corr_a.1_attribute_id = corr_b.1_attribute_id AND
                        corr_a.value_id = corr_b.value_id AND
                        corr_a.id <> corr_b.id
                    GROUP BY uniq
                ) as c
            );
        ");
    }

    public function findOrder($order, $orderModel, $validOrderFields)
    {
        if (is_string($order)) {
            $orderRules = explode(',', $order);
        } elseif (is_array($order)) {
            $orderRules = $order; // to support multiple column order
        }

        $order = array();
        foreach ($orderRules as $rule) {
            if (!is_string($rule)) {
                return null;
            }
            $ruleItems = explode(' ', trim($rule));
            $direction = 'asc';
            if (count($ruleItems) === 2) {
                if (strtolower(end($ruleItems)) === 'asc' || strtolower(end($ruleItems)) === 'desc') {
                    $direction = end($ruleItems);
                }
            }
            $orderPath = explode('.', $ruleItems[0]);
            if (count($orderPath) === 1) {
                $model = $orderModel;
                $field = strtolower($orderPath[0]);
            } elseif (count($orderPath) === 2) {
                $model = $orderPath[0];
                $field = strtolower($orderPath[1]);
            } else {
                return null;
            }
            if (
                    (in_array($field, $validOrderFields) && $model === $orderModel) ||
                    (array_key_exists($model, $validOrderFields) && in_array($field, $validOrderFields[$model]))
            ) {
                $order[] = $model . '.' . $field . ' ' . $direction;
            } else {
                return null;
            }
        }
        if (count($order) > 0) {
           return $order;
        } 
        return null;
    }

    /**
     * @return string|null
     */
    public function _remoteIp()
    {
        static $remoteIp;

        if ($remoteIp) {
            return $remoteIp;
        }

        $clientIpHeader = Configure::read('MISP.log_client_ip_header');
        if ($clientIpHeader && isset($_SERVER[$clientIpHeader])) {
            $headerValue = $_SERVER[$clientIpHeader];
            // X-Forwarded-For can contain multiple IPs, see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For
            if (($commaPos = strpos($headerValue, ',')) !== false) {
                $headerValue = substr($headerValue, 0, $commaPos);
            }
            $remoteIp = trim($headerValue);
        } else {
            $remoteIp = $_SERVER['REMOTE_ADDR'] ?? null;
        }

        return $remoteIp;
    }

    public function find($type = 'first', $query = array())
    {
        if (!empty($query['order']) && $this->validOrderClause($query['order']) === false) {
            throw new InvalidArgumentException('Invalid order clause');
        }
        $results = parent::find($type, $query);
        if (!empty($query['includeAnalystData']) && $this->Behaviors->enabled('AnalystDataParent')) {
            if ($type === 'first') {
                $results[$this->alias] = array_merge($results[$this->alias], $this->attachAnalystData($results[$this->alias]));
            } else if ($type === 'all') {
                foreach ($results as $k => $result) {
                    $results[$k][$this->alias] = array_merge($results[$k][$this->alias], $this->attachAnalystData($results[$k][$this->alias]));
                }
            }
        }
        return $results;
    }

    private function validOrderClause($order)
    {
        $pattern = '/^[\w\_\-\.\(\) ]+$/';
        if (is_string($order) && preg_match($pattern, $order)) {
            return true;
        }

        if (is_array($order)) {
            foreach ($order as $key => $value) {
                if (is_string($key) && is_string($value) && preg_match($pattern, $key) && in_array(strtolower($value), ['asc', 'desc'])) {
                    return true;
                }
                if (is_numeric($key) && is_string($value) && preg_match($pattern, $value)) {
                    return true;
                }
            }
        }

        return false;
    }

    protected function checkParam($param)
    {
        return preg_match('/^[\w\_\-\. ]+$/', $param);
    }

    public function moveImages()
    {
        $oldImageDir = APP . 'webroot/img';
        $newImageDir = APP . 'files/img';
        $oldOrgDir = new Folder($oldImageDir . '/orgs');
        $oldCustomDir = new Folder($oldImageDir . '/custom');
        $result = $oldOrgDir->copy([
            'from' => $oldImageDir . '/orgs',
            'to' => $newImageDir . '/orgs',
            'scheme' => Folder::OVERWRITE,
            'recursive' => true
        ]);
        if ($result) {
            $oldOrgDir->delete();
        }
        $result = $oldCustomDir->copy([
            'from' => $oldImageDir . '/custom',
            'to' => $newImageDir . '/custom',
            'scheme' => Folder::OVERWRITE,
            'recursive' => true
        ]);
        if ($result) {
            $oldCustomDir->delete();
        }
        return true;
    }

    public function getSearchParamsByToken($filters)
    {
        $token = $filters['search_token'];
        $redis = $this->setupRedis();
        if (!$redis) {
            throw new Exception('Could not connect to Redis server');
        }
        $path = 'misp:search_tokens:' . $token;
        $params = $redis->get($path);
        if (empty($params)) {
            throw new NotFoundException(__('Invalid search token or already expired.'));
        }
        $params = json_decode($params, true);
        $params['search_token'] = $token;
        $toUnset = ['page', 'limit', 'sort', 'direction'];
        foreach ($toUnset as $unset) {
            if (isset($params[$unset])) {
                unset($params[$unset]);
            }
        }
        return array_merge($filters, $params);
    }

    public function setSearchParamsByToken($params)
    {
        $redis = $this->setupRedis();
        if (!$redis) {
            throw new Exception('Could not connect to Redis server');
        }
        $token = bin2hex(Security::randomBytes(32));
        $path = 'misp:search_tokens:' . $token;
        $params = json_encode($params);
        $redis->set($path, $params);
        $redis->expire($path, 3600);
        return $token;
    }
    
    public function fixUpdatedGalaxyID()
    {
        $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
        $this->AuditLog = ClassRegistry::init('AuditLog');
        $allUpdatedClusters = $this->AuditLog->find('all', [
            'conditions' => [
                'model' => 'GalaxyCluster',
                'user_id !=' => 0, // Ignore clusters from misp-galaxy
                'action' => ['edit',],
            ],
            'recursive' => -1,
        ]);
        $clusterIDsThatGotTheirGalaxyIDChanged = [];
        foreach ($allUpdatedClusters as $cluster) {
            if (!empty($cluster['AuditLog']['change']['galaxy_id'])) {
                $oldID = $cluster['AuditLog']['change']['galaxy_id'][0];
                $newID = $cluster['AuditLog']['change']['galaxy_id'][1];
                $clusterIDsThatGotTheirGalaxyIDChanged[$cluster['AuditLog']['model_id']] = [$oldID, $newID];
            }
        }
        $clustersThatGotTheirGalaxyIDChanged = $this->GalaxyCluster->find('all', [
            'conditions' => [
                'id' => array_keys($clusterIDsThatGotTheirGalaxyIDChanged),
            ],
            'recursive' => -1,
        ]);
        $toUpdate = [];
        foreach ($clustersThatGotTheirGalaxyIDChanged as $cluster) {
            $oldID = $clusterIDsThatGotTheirGalaxyIDChanged[$cluster['GalaxyCluster']['id']][0];
            $newID = $clusterIDsThatGotTheirGalaxyIDChanged[$cluster['GalaxyCluster']['id']][1];
            if ($oldID !== $newID) {
                $toUpdate[] = [
                    'id' => $cluster['GalaxyCluster']['id'],
                    'galaxy_id' => $oldID,
                ];
                $this->GalaxyCluster->saveMany($toUpdate);
            }
        }

        $options = [
            'validate' => false,
            'callbacks' => false,
        ];
        foreach (array_chunk($toUpdate, 1000) as $chunk) {
            $this->GalaxyCluster->saveMany($chunk, $options);
        }
        return true;
    }

    public function checkDbSupport($functionality)
    {
        if (isset($this->getDataSource()->supports) && !empty($this->getDataSource()->supports[$functionality])) {
            return $this->getDataSource()->supports[$functionality];
        }
        return false;
    }

    /**
     * @param string $column
     * @return string|null The index this column belongs to, if any.
     */
    public function getIndexNameForColumn($column)
    {
        return $this->getSchemaInspector()->indexNameForColumn($this->table, $column);
    }

    /**
     * Same question as checkNamedIndexExists(), kept because both are public
     * and callers exist for each.
     *
     * @param string $table
     * @param string $indexName
     * @return bool
     */
    public function indexExists($table, $indexName)
    {
        return $this->getSchemaInspector()->hasNamedIndex($table, $indexName);
    }
}
