<?php

namespace App\Model\Table;

use App\Lib\Tools\BackgroundJobsTool;
use App\Model\Entity\Job;
use App\Model\Table\AppTable;
use ArrayObject;
use Cake\Event\EventInterface;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\ORM\Locator\LocatorAwareTrait;
use Exception;

class JobsTable extends AppTable
{
    use LocatorAwareTrait;

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->belongsTo(
            'Organisations',
            [
                'dependent' => false,
                'cascadeCallbacks' => false,
                'foreignKey' => 'org_id',
                'propertyName' => 'Organisation'
            ]
        );

        $this->setDisplayField('name');
    }

    public function beforeMarshal(EventInterface $event, ArrayObject $data, ArrayObject $options)
    {
        $date = date('Y-m-d H:i:s');
        if (!isset($data['date_created'])) {
            $data['date_created'] = $date;
        }
        $data['date_modified'] = $date;
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

        $EventsTable = $this->fetchTable('Events');

        if (in_array($type, array_keys($EventsTable->exportTypes())) && $type !== 'bro') {

            BackgroundJobsTool::getInstance()->enqueue(
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

            BackgroundJobsTool::getInstance()->enqueue(
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
        $job = $this->newEntity(
            [
                'worker' => $worker,
                'status' => 0,
                'retries' => 0,
                'org_id' => $user === 'SYSTEM' ? 0 : $user['org_id'],
                'job_type' => $jobType,
                'job_input' => $jobInput,
                'message' => $message,
            ]
        );

        if (!$this->save($job, ['atomic' => false])) { // no need to start transaction for single insert
            throw new Exception("Could not save job.");
        }
        return $job->id;
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

        $jobData = [
            $this->primaryKey => $jobId,
        ];
        if ($message !== null) {
            $jobData['message'] = $message;
        }
        if ($progress !== null) {
            $jobData['progress'] = $progress;
            if ($progress >= 100) {
                $jobData['status'] = Job::STATUS_COMPLETED;
            }
        }
        $jobEntity = $this->newEntity($jobData);
        try {
            if ($this->save($jobEntity, ['atomic' => false])) {
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

        $jobData = $this->newEntity(
            [
                $this->primaryKey => $jobId,
                'status' => $success ? Job::STATUS_COMPLETED : Job::STATUS_FAILED,
                'message' => $message,
                'progress' => 100,
            ]
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
