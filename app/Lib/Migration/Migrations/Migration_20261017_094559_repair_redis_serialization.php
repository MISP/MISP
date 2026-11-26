<?php

App::uses('AbstractMigration', 'Migration');
App::uses('BackgroundJobsTool', 'Tools');
App::uses('Job', 'Model');

/**
 * Queue the repair of the values in Redis that requests had stored
 * PHP-serialized while browscap's cache held their connection. Without
 * background jobs it only says which command to run: a large Redis database
 * takes minutes, too long for an upgrade that runs inside a login.
 */
class Migration_20261017_094559_repair_redis_serialization extends AbstractMigration
{
    public $description = 'Queue the repair of PHP-serialized values in Redis';

    /**
     * Nothing the session data is built from changes.
     *
     * @var bool
     */
    public $requiresLogout = false;

    const JOB_TYPE = 'repair redis serialization';

    const COMMAND = 'Console/cake Admin redisRepairSerialization';

    /**
     * No DDL.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
    }

    /**
     * A repair that cannot be queued is logged with its command instead of
     * failing the migration: it must not hold back the migrations after it.
     *
     * @return bool
     */
    public function afterUp()
    {
        if (!Configure::read('MISP.background_jobs')) {
            $this->logLine(__('Background jobs are off: run %s once to repair the values in Redis stored PHP-serialized.', self::COMMAND));
            return true;
        }
        $Job = ClassRegistry::init('Job');
        $jobId = $Job->createJob('SYSTEM', Job::WORKER_DEFAULT, self::JOB_TYPE, $this->id(), 'Queued by the upgrade.');
        try {
            $Job->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_ADMIN,
                array('redisRepairSerialization', $jobId),
                true,
                $jobId
            );
        } catch (Exception $e) {
            $message = __('Could not be queued (%s): run %s once.', $e->getMessage(), self::COMMAND);
            $Job->saveStatus($jobId, false, $message);
            $this->logLine(__('Redis repair: %s', $message));
        }
        return true;
    }

    /**
     * @param string $title
     * @return void
     */
    private function logLine($title)
    {
        $Log = ClassRegistry::init('Log');
        $Log->create();
        $Log->saveOrFailSilently(array(
            'org' => 'SYSTEM',
            'model' => 'Server',
            'model_id' => 0,
            'email' => 'SYSTEM',
            'action' => 'update_database',
            'user_id' => 0,
            'title' => $title,
            'change' => '',
        ));
    }
}
