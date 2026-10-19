<?php

App::uses('AbstractMigration', 'Migration');
App::uses('BackgroundJobsTool', 'Tools');
App::uses('Job', 'Model');

/**
 * Queue the full recorrelation that refills the correlation tables the
 * upgrade recreated empty. Without background jobs it only says which command
 * to run: recorrelating here would hold the upgrade for hours.
 */
class Migration_20261016_204637_queue_full_recorrelation extends AbstractMigration
{
    public $description = 'Queue the full recorrelation of the recreated correlation tables';

    /**
     * Nothing the session data is built from changes.
     *
     * @var bool
     */
    public $requiresLogout = false;

    const JOB_TYPE = 'generate correlation';

    const COMMAND = 'Console/cake Admin jobGenerateCorrelation';

    /** @var array|null */
    private $decision = null;

    /**
     * No DDL. The decision is noted, so that it reaches the update log and the
     * dry run.
     *
     * @param SchemaBuilder $schema
     * @return void
     */
    public function up(SchemaBuilder $schema)
    {
        $schema->note($this->decision()['line']);
    }

    /**
     * @return array
     */
    public function forecast()
    {
        return array($this->decision()['line']);
    }

    /**
     * @return bool
     * @throws Exception When the job cannot be queued; its row is marked failed
     *   first, so a re-run queues a new one.
     */
    public function afterUp()
    {
        if (!in_array($this->decision()['action'], array('queue', 'queued'), true)) {
            return true;
        }
        // A worker that is already running starts the job in a new process,
        // which must not read the tables as they were before the upgrade.
        $this->inspector()->flushSchemaCacheFiles();
        ClassRegistry::init('Job')->enqueueOnce(
            'SYSTEM',
            Job::WORKER_DEFAULT,
            self::JOB_TYPE,
            $this->id(),
            'Queued by the upgrade.',
            BackgroundJobsTool::DEFAULT_QUEUE,
            BackgroundJobsTool::CMD_ADMIN,
            array('jobGenerateCorrelation')
        );
        return true;
    }

    /**
     * What to do, from what the instance holds.
     *
     * @param array $state disabled, engine, table (null when the engine keeps
     *   none), correlated, attributes, backgroundJobs, pendingJob (the id of
     *   the queued or running job, or null), unqueuedJob (the id of a waiting
     *   row an interrupted run left unqueued, or null)
     * @return array action ('none', 'command', 'queue' or 'queued': afterUp()
     *   then records the job's id in its row if an interrupted run did not), line
     */
    public static function decide(array $state)
    {
        if ($state['disabled']) {
            return self::outcome('none', 'Correlation is disabled (MISP.completely_disable_correlation): nothing to recorrelate. Enabling it queues a full recorrelation.');
        }
        if ($state['table'] === null) {
            return self::outcome('none', sprintf('The %s correlation engine stores no correlations: nothing to recorrelate.', $state['engine']));
        }
        if ($state['correlated']) {
            return self::outcome('none', sprintf('%s already holds correlations: no recorrelation queued.', $state['table']));
        }
        if (!$state['attributes']) {
            return self::outcome('none', 'No attributes: nothing to recorrelate.');
        }
        if (!$state['backgroundJobs']) {
            return self::outcome('command', sprintf('Background jobs are off, so %s stays empty until a full recorrelation runs. Once the instance is back: %s (on a large instance it takes hours).', $state['table'], self::COMMAND));
        }
        if ($state['pendingJob'] !== null) {
            return self::outcome('queued', sprintf('The full recorrelation is already queued or running (job %d): not queueing another.', $state['pendingJob']));
        }
        if ($state['unqueuedJob'] !== null) {
            return self::outcome('queue', sprintf('Queues the full recorrelation an interrupted run left unqueued (job %d) to refill %s; a default worker runs it, and the instance can be live meanwhile.', $state['unqueuedJob'], $state['table']));
        }
        return self::outcome('queue', sprintf('Queues a full recorrelation to refill %s; a default worker runs it, and the instance can be live meanwhile.', $state['table']));
    }

    /**
     * @param string $action
     * @param string $line
     * @return array
     */
    private static function outcome($action, $line)
    {
        return array('action' => $action, 'line' => $line);
    }

    /**
     * @return array
     */
    private function decision()
    {
        if ($this->decision === null) {
            $this->decision = self::decide($this->state());
        }
        return $this->decision;
    }

    /**
     * @return array
     */
    private function state()
    {
        $Correlation = ClassRegistry::init('Correlation');
        $table = null;
        $correlated = false;
        // The On Demand engine points the model at default_correlations too.
        if (!$Correlation->onDemandEngine()) {
            $table = $Correlation->useTable;
            $correlated = !empty($Correlation->find('first', array(
                'recursive' => -1,
                'fields' => array('Correlation.id'),
            )));
        }
        $attribute = ClassRegistry::init('MispAttribute')->find('first', array(
            'recursive' => -1,
            'fields' => array('Attribute.id'),
        ));
        $backgroundJobs = (bool)Configure::read('MISP.background_jobs');
        $pendingJob = $unqueuedJob = null;
        if ($backgroundJobs) {
            $Job = ClassRegistry::init('Job');
            $pending = $Job->pendingJob(self::JOB_TYPE, $this->id());
            if ($pending !== null) {
                if ($Job->queuedProcessId($pending, BackgroundJobsTool::DEFAULT_QUEUE) !== null) {
                    $pendingJob = (int)$pending['id'];
                } else {
                    $unqueuedJob = (int)$pending['id'];
                }
            }
        }
        return array(
            'disabled' => (bool)Configure::read('MISP.completely_disable_correlation'),
            'engine' => $Correlation->getCorrelationModelName(),
            'table' => $table,
            'correlated' => $correlated,
            'attributes' => !empty($attribute),
            'backgroundJobs' => $backgroundJobs,
            'pendingJob' => $pendingJob,
            'unqueuedJob' => $unqueuedJob,
        );
    }
}
