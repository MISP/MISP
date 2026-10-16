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
        if ($this->decision()['action'] !== 'queue') {
            return true;
        }
        // A worker that is already running starts the job in a new process,
        // which must not read the tables as they were before the upgrade.
        $this->inspector()->flushSchemaCacheFiles();
        $Job = ClassRegistry::init('Job');
        $jobId = $Job->createJob('SYSTEM', Job::WORKER_DEFAULT, self::JOB_TYPE, $this->id(), 'Queued by the upgrade.');
        try {
            $Job->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_ADMIN,
                array('jobGenerateCorrelation', $jobId),
                true,
                $jobId
            );
        } catch (Exception $e) {
            $Job->saveStatus($jobId, false, 'Could not be queued: ' . $e->getMessage());
            throw $e;
        }
        return true;
    }

    /**
     * What to do, from what the instance holds.
     *
     * @param array $state disabled, engine, table (null when the engine keeps
     *   none), correlated, attributes, backgroundJobs, pendingJob (an id or null)
     * @return array action ('none', 'command' or 'queue'), line
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
            return self::outcome('none', sprintf('The full recorrelation is already queued or running (job %d): not queueing another.', $state['pendingJob']));
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
        // Only this migration's own job: rows of jobs that died stay waiting
        // or running for ever, and must not stop the queueing.
        $pending = ClassRegistry::init('Job')->find('first', array(
            'recursive' => -1,
            'fields' => array('Job.id'),
            'conditions' => array(
                'Job.job_type' => self::JOB_TYPE,
                'Job.job_input' => $this->id(),
                'Job.status' => array(0, Job::STATUS_WAITING, Job::STATUS_RUNNING),
            ),
            'order' => array('Job.id' => 'DESC'),
        ));
        return array(
            'disabled' => (bool)Configure::read('MISP.completely_disable_correlation'),
            'engine' => $Correlation->getCorrelationModelName(),
            'table' => $table,
            'correlated' => $correlated,
            'attributes' => !empty($attribute),
            'backgroundJobs' => (bool)Configure::read('MISP.background_jobs'),
            'pendingJob' => empty($pending) ? null : (int)$pending['Job']['id'],
        );
    }
}
