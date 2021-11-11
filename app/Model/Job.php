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
        WORKER_CACHE = 'cache';

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

    public function cache($type, $user)
    {
        $jobId = $this->createJob(
            $user,
            Job::WORKER_CACHE,
            'cache_' . $type,
            $user['Role']['perm_site_admin'] ? 'All events.' : 'Events visible to: ' . $user['Organisation']['name'],
            'Fetching events.'
        );

        $this->Event = ClassRegistry::init('Event');

        if (in_array($type, array_keys($this->Event->export_types)) && $type !== 'bro') {

            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::CACHE_QUEUE,
                BackgroundJobsTool::CMD_EVENT,
                [
                    'cache',
                    $user['id'],
                    $jobId,
                    $type
                ],
                true,
                $jobId
            );
        } elseif ($type === 'bro') {

            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::CACHE_QUEUE,
                BackgroundJobsTool::CMD_EVENT,
                [
                    'cachebro',
                    $user['id'],
                    $jobId,
                    $type
                ],
                true,
                $jobId
            );
        } else {
            throw new MethodNotAllowedException('Invalid export type.');
        }

        return $jobId;
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
}
