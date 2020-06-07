<?php
App::uses('AppModel', 'Model');

class Job extends AppModel
{
    const STATUS_WAITING = 1;
    const STATUS_RUNNING = 2;
    const STATUS_FAILED = 3;
    const STATUS_COMPLETED = 4;

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
        parent::beforeValidate();
        $date = date('Y-m-d H:i:s');
        if (empty($this->data['Job']['id'])) {
            $this->data['Job']['date_created'] = $date;
            $this->data['Job']['date_modified'] = $date;
        } else {
            $this->data['Job']['date_modified'] = $date;
        }
    }

    public function cache($type, $user)
    {
        $extra = null;
        $extra2 = null;
        $shell = 'Event';
        $this->create();
        $data = array(
                'worker' => 'cache',
                'job_type' => 'cache_' . $type,
                'job_input' => $user['Role']['perm_site_admin'] ? 'All events.' : 'Events visible to: ' . $user['Organisation']['name'],
                'status' => 0,
                'retries' => 0,
                'org_id' => $user['Role']['perm_site_admin'] ? 0 : $user['org_id'],
                'message' => 'Fetching events.',
        );
        $this->save($data);
        $id = $this->id;
        $this->Event = ClassRegistry::init('Event');
        if (in_array($type, array_keys($this->Event->export_types)) && $type !== 'bro') {
            $process_id = CakeResque::enqueue(
                    'cache',
                    $shell . 'Shell',
                    array('cache', $user['id'], $id, $type),
                    true
            );
        } elseif ($type === 'bro') {
            $type = 'bro';
            $process_id = CakeResque::enqueue(
                    'cache',
                    $shell . 'Shell',
                    array('cachebro', $user['id'], $id),
                    true
            );
        } else {
            throw new MethodNotAllowedException('Invalid export type.');
        }
        $this->saveField('process_id', $process_id);
        return $id;
    }

    /**
     * @param int|null $jobId
     * @param string|null $message
     * @param int|null $progress
     * @return bool
     */
    public function saveProgress($jobId = null, $message = null, $progress = null)
    {
        if ($jobId) {
            $jobData = array($this->primaryKey => $jobId);
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
                $this->save($jobData);
                return true;
            } catch (Exception $e) {
                // ignore error during saving information about job
                return false;
            }
        }

        return null;
    }
}
