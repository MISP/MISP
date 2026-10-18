<?php
App::uses('AppModel', 'Model');

class Job extends AppModel
{
    const STATUS_WAITING = 1,
        STATUS_RUNNING = 2,
        STATUS_FAILED = 3,
        STATUS_COMPLETED = 4;

    const WORKER_EMAIL = 'email',
        WORKER_PRIO = 'prio',
        WORKER_DEFAULT = 'default',
        WORKER_CACHE = 'cache',
        WORKER_UPDATE = 'update';

    public $actsAs = array('Containable');

    public $belongsTo = array(
        'Org' => array(
            'className' => 'Organisation',
            'foreignKey' => 'org_id',
            'order' => array(),
            'fields' => array('id', 'name', 'uuid')
        ),
    );

    public function beforeValidate($options = array())
    {
        $date = date('Y-m-d H:i:s');
        if (empty($this->data['Job']['id'])) {
            $this->data['Job']['date_created'] = $date;
        }
        $this->data['Job']['date_modified'] = $date;
    }

    /**
     * @param array|string $user
     * @param string $worker
     * @param string $jobType
     * @param string$jobInput
     * @param string $message
     * @return int Job ID
     * @throws Exception
     */
    public function createJob($user, $worker, $jobType, $jobInput, $message = '')
    {
        $job = [
            'worker' => $worker,
            'status' => 0,
            'retries' => 0,
            'org_id' => $user === 'SYSTEM' ? 0 : $user['org_id'],
            'job_type' => $jobType,
            'job_input' => $jobInput,
            'message' => $message,
        ];
        $this->create();
        if (!$this->save($job, ['atomic' => false])) { // no need to start transaction for single insert
            throw new Exception("Could not save job.");
        }
        return (int)$this->id;
    }

    /**
     * Queue a job unless one of this type and input is already queued or
     * running. A process killed between the row and the enqueue leaves a row
     * without a process id; that row is queued now, unless Redis holds its job.
     *
     * @param array|string $user
     * @param string $worker
     * @param string $jobType
     * @param string $jobInput
     * @param string $message
     * @param string $queue
     * @param string $command
     * @param array $args The job id is appended.
     * @return array The job id, and whether it was queued now.
     * @throws Exception When it cannot be queued; the row is marked failed first.
     */
    public function enqueueOnce($user, $worker, $jobType, $jobInput, $message, $queue, $command, array $args)
    {
        $pending = $this->pendingJob($jobType, $jobInput);
        if ($pending !== null) {
            $jobId = (int)$pending['id'];
            $processId = $this->queuedProcessId($pending, $queue);
            if ($processId !== null) {
                if (empty($pending['process_id'])) {
                    $this->save(['id' => $jobId, 'process_id' => $processId], ['atomic' => false]);
                }
                return [$jobId, false];
            }
        } else {
            $jobId = $this->createJob($user, $worker, $jobType, $jobInput, $message);
        }
        $args[] = $jobId;
        try {
            $this->getBackgroundJobsTool()->enqueue($queue, $command, $args, true, $jobId);
        } catch (Exception $e) {
            $this->saveStatus($jobId, false, __('Could not be queued: %s', $e->getMessage()));
            throw $e;
        }
        return [$jobId, true];
    }

    /**
     * The newest row of this type and input that is waiting or running.
     *
     * @param string $jobType
     * @param string $jobInput
     * @return array|null id, process_id
     */
    public function pendingJob($jobType, $jobInput)
    {
        $job = $this->find('first', [
            'recursive' => -1,
            'fields' => ['Job.id', 'Job.process_id'],
            'conditions' => [
                'Job.job_type' => $jobType,
                'Job.job_input' => $jobInput,
                'Job.status' => [0, self::STATUS_WAITING, self::STATUS_RUNNING],
            ],
            'order' => ['Job.id' => 'DESC'],
        ]);
        return empty($job) ? null : $job['Job'];
    }

    /**
     * @param array $job As pendingJob() returns it.
     * @param string $queue
     * @return string|null The id of its job in Redis; null when it is not queued.
     */
    public function queuedProcessId(array $job, $queue)
    {
        if (!empty($job['process_id'])) {
            return $job['process_id'];
        }
        $queued = $this->getBackgroundJobsTool()->findQueuedJob($queue, (int)$job['id']);
        return $queued === null ? null : $queued->id();
    }

    /**
     * @param int|null $jobId
     * @param string|null $message
     * @param int|null $progress
     * @return bool|null
     */
    public function saveProgress($jobId = null, $message = null, $progress = null)
    {
        if ($jobId === null) {
            return null;
        }

        $jobData = array(
            $this->primaryKey => $jobId,
        );
        if ($message !== null) {
            $jobData['message'] = $message;
        }
        if ($progress !== null) {
            $jobData['progress'] = $progress;
            if ($progress >= 100) {
                $jobData['status'] = self::STATUS_COMPLETED;
            }
        }
        try {
            if ($this->save($jobData, ['atomic' => false])) {
                return true;
            }
            $this->log("Could not save progress for job $jobId because of validation errors: " . json_encode($this->validationErrors), LOG_NOTICE);
        } catch (Exception $e) {
            $this->logException("Could not save progress for job $jobId", $e, LOG_NOTICE);
        }
        return false;
    }

    /**
     * @param int|null $jobId
     * @param bool $success
     * @param string|null $message
     * @return bool|null
     */
    public function saveStatus($jobId = null, $success = true, $message = null)
    {
        if ($jobId === null) {
            return null;
        }

        if (!$message) {
            $message = $success ? __('Job done.') : __('Job failed.');
        }

        $jobData = array(
            $this->primaryKey => $jobId,
            'status' => $success ? self::STATUS_COMPLETED : self::STATUS_FAILED,
            'message' => $message,
            'progress' => 100,
        );

        try {
            if ($this->save($jobData)) {
                return true;
            }
            $this->log("Could not save status for job $jobId because of validation errors: " . json_encode($this->validationErrors), LOG_NOTICE);
        } catch (Exception $e) {
            $this->logException("Could not save progress for job $jobId", $e, LOG_NOTICE);
        }
        return false;
    }

    /**
     * Records how a job's process ended, unless the job already marked its row
     * failed or completed itself.
     *
     * @param int $jobId
     * @param bool $success
     * @param string|null $message
     * @return bool
     */
    public function saveExitStatus($jobId, $success, $message = null)
    {
        $job = $this->find('first', [
            'conditions' => ['Job.id' => $jobId],
            'fields' => ['Job.status'],
            'recursive' => -1,
        ]);
        if (empty($job) || in_array((int)$job['Job']['status'], [self::STATUS_FAILED, self::STATUS_COMPLETED], true)) {
            return false;
        }
        return $this->saveStatus($jobId, $success, $message);
    }
}
