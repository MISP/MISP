<?php
App::uses('AppController', 'Controller');

/**
 * @property Job $Job
 */
class JobsController extends AppController
{
    public $components = array('Security' ,'RequestHandler', 'Session');

    public $paginate = array(
        'limit' => 20,
        'recursive' => 0,
        'order' => array(
            'Job.id' => 'desc'
        ),
    );

    public function index($queue = false)
    {
        if (!Configure::read('MISP.background_jobs')) {
            throw new NotFoundException('Background jobs are not enabled on this instance.');
        }
        $this->loadModel('Server');
        $issueCount = 0;
        $workers = $this->Server->workerDiagnostics($issueCount);
        $queues = array('email', 'default', 'cache', 'prio', 'update');
        if ($queue && in_array($queue, $queues, true)) {
            $this->paginate['conditions'] = array('Job.worker' => $queue);
        }
        $jobs = $this->paginate();
        foreach ($jobs as &$job) {
            if ($job['Job']['process_id'] !== false) {
                $job['Job']['job_status'] = $this->__jobStatusConverter(CakeResque::getJobStatus($job['Job']['process_id']));
                $job['Job']['failed'] = $job['Job']['job_status'] === 'Failed';
            } else {
                $job['Job']['job_status'] = 'Unknown';
            }
            $job['Job']['worker_status'] = isset($workers[$job['Job']['worker']]) && $workers[$job['Job']['worker']]['ok'];
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($jobs, $this->response->type());
        }
        $this->set('list', $jobs);
        $this->set('queue', $queue);
    }

    public function getError($id)
    {
        $fields = array(
            'Failed at' => 'failed_at',
            'Exception' => 'exception',
            'Error' => 'error'
        );
        $this->set('fields', $fields);
        $this->set('response', CakeResque::getFailedJobLog($id));
        $this->render('/Jobs/ajax/error');
    }

    private function __jobStatusConverter($status)
    {
        switch ($status) {
            case 1:
                return 'Waiting';
            case 2:
                return 'Running';
            case 3:
                return 'Failed';
            case 4:
                return 'Completed';
            default:
                return 'Unknown';
        }
    }

    public function getGenerateCorrelationProgress($id)
    {
        $job = $this->Job->find('first', [
            'fields' => ['progress', 'process_id'],
            'conditions' => ['id' => $id],
            'recursive' => -1,
        ]);
        if (!$job) {
            throw new NotFoundException("Job with ID `$id` not found");
        }
        $output = [
            'job_status' => $this->__jobStatusConverter(CakeResque::getJobStatus($job['Job']['process_id'])),
            'progress' => (int)$job['Job']['progress'],
        ];
        return $this->RestResponse->viewData($output, 'json');
    }

    public function getProgress($type)
    {
        $org_id = $this->Auth->user('org_id');
        if ($this->_isSiteAdmin()) {
            $org_id = 0;
        }

        if (is_numeric($type)) {
            $progress = $this->Job->find('first', array(
                'conditions' => array(
                    'Job.id' => $type,
                    'org_id' => $org_id
                ),
                'fields' => array('id', 'progress'),
                'order' => array('Job.id' => 'desc'),
            ));
        } else {
            $progress = $this->Job->find('first', array(
                'conditions' => array(
                    'job_type' => $type,
                    'org_id' => $org_id
                ),
                'fields' => array('id', 'progress'),
                'order' => array('Job.id' => 'desc'),
            ));
        }
        if (!$progress) {
            $progress = 0;
        } else {
            $progress = $progress['Job']['progress'];
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData(array('progress' => $progress . '%'), $this->response->type());
        } else {
            return new CakeResponse(array('body' => json_encode($progress), 'type' => 'json'));
        }
    }

    public function cache($type)
    {
        if (Configure::read('MISP.disable_cached_exports')) {
            throw new MethodNotAllowedException('This feature is currently disabled');
        }
        if ($this->_isSiteAdmin()) {
            $target = 'All events.';
        } else {
            $target = 'Events visible to: '.$this->Auth->user('Organisation')['name'];
        }
        $id = $this->Job->cache($type, $this->Auth->user());
        if ($this->_isRest()) {
            return $this->RestResponse->viewData(array('job_id' => $id), $this->response->type());
        } else {
            return new CakeResponse(array('body' => json_encode($id), 'type' => 'json'));
        }
    }

    public function clearJobs($type = 'completed')
    {
        if ($this->request->is('post')) {
            if ($type === 'all') {
                $conditions = array('Job.id !=' => 0);
                $message = __('All jobs have been purged');
            } else {
                $conditions = array('Job.progress' => 100);
                $message = __('All completed jobs have been purged');
            }
            $this->Job->deleteAll($conditions, false);
            $this->Flash->success($message);
            $this->redirect(array('action' => 'index'));
        }
    }
}
