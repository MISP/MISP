<?php

namespace App\Controller;

use App\Controller\AppController;
use App\Lib\Tools\BackgroundJobsTool;
use Cake\Core\Configure;
use Cake\Event\EventInterface;
use Cake\Http\Exception\MethodNotAllowedException;
use Cake\Http\Exception\NotFoundException;
use Cake\Http\Response;
use Cake\ORM\Locator\LocatorAwareTrait;

class JobsController extends AppController
{
    use LocatorAwareTrait;

    public $paginate = [
        'limit' => 20,
        'recursive' => 0,
        'order' => [
            'Job.id' => 'DESC'
        ],
        'contain' => [
            'Organisations' => [
                'fields' => ['id', 'name', 'uuid'],
            ],
        ]
    ];

    public function beforeFilter(EventInterface $event)
    {
        parent::beforeFilter($event);
        if ($this->request->getParam('action') === 'getGenerateCorrelationProgress') {
            $this->Security->doNotGenerateToken = true;
        }
    }

    public function index($queue = false)
    {
        if (!Configure::read('BackgroundJobs.enabled')) {
            throw new NotFoundException('Background jobs are not enabled on this instance.');
        }
        $ServerTable = $this->fetchTable('Servers');
        $issueCount = 0;
        $workers = $ServerTable->workerDiagnostics($issueCount);
        $queues = ['email', 'default', 'cache', 'prio', 'update'];
        if ($queue && in_array($queue, $queues, true)) {
            $this->paginate['conditions'] = ['Job.worker' => $queue];
        }
        $jobs = $this->paginate()->toArray();
        foreach ($jobs as &$job) {
            if (!empty($job['process_id'])) {
                $job['job_status'] = $this->getJobStatus($job['process_id']);
                $job['failed'] = $job['job_status'] === 'Failed';
            } else {
                $job['job_status'] = 'Unknown';
                $job['failed'] = null;
            }
            if (Configure::read('BackgroundJobs.enabled')) {
                $job['worker_status'] = true;
            } else {
                $job['worker_status'] = isset($workers[$job['worker']]) && $workers[$job['worker']]['ok'];
            }
        }
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData($jobs);
        }
        $this->set('jobs', $jobs);
        $this->set('queue', $queue);
    }

    public function getError($id)
    {
        $fields = [
            'Failed at' => 'failed_at',
            'Exception' => 'exception',
            'Error' => 'error'
        ];
        $this->set('fields', $fields);
        $this->set('response', $this->getFailedJobLog($id));
        $this->render('/Jobs/ajax/error');
    }

    private function jobStatusConverter($status)
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

    public function getGenerateCorrelationProgress($ids)
    {
        $this->closeSession();

        $ids = explode(",", $ids);
        $jobs = $this->Jobs->find(
            'all',
            [
                'fields' => ['id', 'progress', 'process_id'],
                'conditions' => ['id' => $ids],
                'recursive' => -1,
            ]
        );
        if (empty($jobs)) {
            throw new NotFoundException('No jobs found');
        }

        $output = [];
        foreach ($jobs as $job) {
            $output[$job['id']] = [
                'job_status' => $this->getJobStatus($job['process_id']),
                'progress' => (int)$job['progress'],
            ];
        }
        return $this->RestResponse->viewData($output, 'json');
    }

    public function getProgress($type)
    {
        $org_id = $this->Auth->user('org_id');
        if ($this->isSiteAdmin()) {
            $org_id = 0;
        }

        if (is_numeric($type)) {
            $progress = $this->Jobs->find(
                'all',
                [
                    'conditions' => [
                        'Job.id' => $type,
                        'org_id' => $org_id
                    ],
                    'fields' => ['id', 'progress'],
                    'order' => ['Job.id' => 'desc'],
                ]
            )->first();
        } else {
            $progress = $this->Jobs->find(
                'all',
                [
                    'conditions' => [
                        'job_type' => $type,
                        'org_id' => $org_id
                    ],
                    'fields' => ['id', 'progress'],
                    'order' => ['Job.id' => 'desc'],
                ]
            )->first();
        }
        if (!$progress) {
            $progress = 0;
        } else {
            $progress = $progress['progress'];
        }
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData(['progress' => $progress . '%']);
        } else {
            return new Response(['body' => json_encode($progress), 'type' => 'json']);
        }
    }

    public function cache($type)
    {
        if (Configure::read('MISP.disable_cached_exports')) {
            throw new MethodNotAllowedException('This feature is currently disabled');
        }
        if ($this->isSiteAdmin()) {
            $target = 'All events.';
        } else {
            $target = 'Events visible to: ' . $this->Auth->user('Organisation')['name'];
        }
        $id = $this->Job->cache($type, $this->ACL->getUser());
        if ($this->ParamHandler->isRest()) {
            return $this->RestResponse->viewData(['job_id' => $id]);
        } else {
            return new Response(['body' => json_encode($id), 'type' => 'json']);
        }
    }

    public function clearJobs($type = 'completed')
    {
        if ($this->request->is('post')) {
            if ($type === 'all') {
                $conditions = ['Job.id !=' => 0];
                $message = __('All jobs have been purged');
            } else {
                $conditions = ['Job.progress' => 100];
                $message = __('All completed jobs have been purged');
            }
            $this->Jobs->deleteAll($conditions, false);
            $this->Flash->success($message);
            $this->redirect(['action' => 'index']);
        }
    }

    private function getJobStatus($id): string
    {
        $status = null;
        if (!empty($id)) {
            $job = BackgroundJobsTool::getInstance()->getJob($id);
            $status = $job ? $job->status() : $status;
        }

        return $this->jobStatusConverter($status);
    }

    private function getFailedJobLog(string $id): array
    {
        $job = BackgroundJobsTool::getInstance()->getJob($id);
        $output = $job ? $job->output() : __('Job status not found.');
        $backtrace = $job ? explode("\n", $job->error()) : [];

        return [
            'error' => $output ?? $backtrace[0] ?? '',
            'backtrace' => $backtrace
        ];
    }
}
