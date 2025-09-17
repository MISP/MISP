<?php

App::uses('AppController', 'Controller');
App::uses('SchedulerWorkerShell', 'Console/Command');

/**
 * @property Task $Task
 * @property Server $Server
 * @property Feed $Feed
 * @property Workflow $Workflow
 */

class TasksController extends AppController
{
    public $components = [
        'CRUD',
        'RequestHandler'
    ];

    public $paginate = [
        'limit' => 60,
        'recursive' => -1,
        'order' => [
            'Task.id' => 'ASC',
        ]
    ];

    public function index()
    {
        if (!$this->_isSiteAdmin()) {
            throw new MethodNotAllowedException('You are not authorised to do that.');
        }

        $this->CRUD->index([
            'contain' => ['User.id', 'User.email', 'Job'],
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }

        $workers = $this->Task->getBackgroundJobsTool()->getWorkers();

        $schedulerEnabled = false;
        foreach ($workers as $worker) {
            if ($worker->queue() === BackgroundJobsTool::SCHEDULER_QUEUE) {
                $schedulerEnabled = true;
                break;
            }
        }

        $this->set('schedulerEnabled', $schedulerEnabled);
    }

    public function toggleEnabled($id)
    {
        if (!$this->_isSiteAdmin()) {
            throw new MethodNotAllowedException('You are not authorised to do that.');
        }

        $task = $this->Task->find('first', array(
            'recursive' => -1,
            'conditions' => array('Task.id' => $id)
        ));
        if (empty($task)) {
            return $this->RestResponse->saveFailResponse('Task', 'toggleEnabled', $id, 'Invalid Task', $this->response->type());
        }
        if ($this->request->is('post')) {
            $task['Task']['enabled'] = !$task['Task']['enabled'];
            $result = $this->Task->save($task);
            if ($result) {
                return $this->RestResponse->saveSuccessResponse('Task', 'toggleEnabled', $id, $this->response->type());
            } else {
                return $this->RestResponse->saveFailResponse('Task', 'toggleEnabled', $id, $this->validationError, $this->response->type());
            }
        }

        $this->set('enabled', !$task['Task']['enabled']);
        $this->set('id', $id);
        $this->autoRender = false;
        $this->layout = false;
        $this->render('ajax/toggle_enabled');
    }

    public function add()
    {
        if (!$this->_isSiteAdmin()) {
            throw new MethodNotAllowedException('You are not authorised to do that.');
        }

        $this->set('dropdownData', $this->__getDropdownData());

        if ($this->request->is('post')) {

            $this->request->data['Task']['message'] = '';
            $this->request->data = $this->__massageFormInput($this->request->data);

            $this->CRUD->add();
            if ($this->restResponsePayload) {
                return $this->restResponsePayload;
            }
        }

        $this->set('menuData', [
            'menuList' => 'admin',
            'menuItem' => 'tasks',
        ]);
    }

    public function edit($id)
    {
        if (!$this->_isSiteAdmin()) {
            throw new MethodNotAllowedException('You are not authorised to do that.');
        }

        $this->set('dropdownData', $this->__getDropdownData());

        if ($this->request->is('put')) {
            $this->request->data = $this->__massageFormInput($this->request->data);
            $this->CRUD->edit($id);
            if ($this->restResponsePayload) {
                return $this->restResponsePayload;
            }
        } else {
            $this->CRUD->edit($id, [
                'afterFind' => function (array $task) {
                    if (isset($task['Task']['params'])) {
                        $params = explode(',', $task['Task']['params']);
                        if ($task['Task']['type'] === 'Server') {
                            $task['Task']['server_id'] = $params[0];
                            $task['Task']['server_action'] = $task['Task']['action'];

                            if ($task['Task']['action'] === 'pull') {
                                $task['Task']['server_technique'] = $params[1];
                            }
                        } elseif ($task['Task']['type'] === 'Feed') {
                            $task['Task']['feed_action'] = $task['Task']['action'];
                            if ($task['Task']['action'] === 'fetch') {
                                $task['Task']['feed_id'] = $params[0];
                            } elseif ($task['Task']['action'] === 'cache') {
                                $task['Task']['feed_id'] = $params[0];
                                if ($task['Task']['feed_id'] !== 'all') {
                                    $task['Task']['feed_scope'] = '';
                                }
                                if (isset($params[1])) {
                                    $task['Task']['feed_scope'] = $params[1];
                                }
                            }
                        }
                    }

                    if (isset($task['Task']['next_execution_time'])) {
                        $task['Task']['next_execution_date'] = date('Y-m-d', $task['Task']['next_execution_time']);
                        $task['Task']['next_execution_time'] = date('H:i:s', $task['Task']['next_execution_time']);
                    } else {
                        $task['Task']['next_execution_date'] = '';
                        $task['Task']['next_execution_time'] = '';
                    }

                    if (isset($task['Task']['timer']) && $task['Task']['timer'] > 0) {
                        $timer = (int)$task['Task']['timer'];
                        $units = [86400, 3600, 60, 1]; // Days, hours, minutes, seconds
                        foreach ($units as $unit) {
                            if ($timer >= $unit && $timer % $unit === 0) {
                                $task['Task']['time_multiplier'] = $timer / $unit;
                                $task['Task']['time_unit'] = $unit;
                                break;
                            }
                        }
                        // Fallback if timer doesn't match a unit
                        if (!isset($task['Task']['time_multiplier'])) {
                            $task['Task']['time_multiplier'] = $timer;
                            $task['Task']['time_unit'] = 1; // Default to seconds
                        }
                    } else {
                        $task['Task']['time_multiplier'] = 1;
                        $task['Task']['time_unit'] = 86400; // Default to 1 day
                    }

                    return $task;
                },
                'fields' => ['type', 'action', 'params', 'timer', 'next_execution_time', 'enabled'],
                'contain' => ['User.id']
            ]);

            if ($this->restResponsePayload) {
                return $this->restResponsePayload;
            }

            $this->set('edit', true);
            $this->set('menuData', [
                'menuList' => 'admin',
                'menuItem' => 'tasks',
            ]);
            $this->render('add');
        }
    }

    public function delete($id)
    {
        if (!$this->_isSiteAdmin()) {
            throw new MethodNotAllowedException('You are not authorised to do that.');
        }
        $this->CRUD->delete($id);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function forceRun($id)
    {
        if (!$this->_isSiteAdmin()) {
            throw new MethodNotAllowedException('You are not authorised to do that.');
        }

        $task = $this->Task->find('first', array(
            'recursive' => -1,
            'conditions' => array('Task.id' => $id)
        ));

        if (empty($task)) {
            if ($this->IndexFilter->isRest()) {
                return $this->RestResponse->saveFailResponse('Task', 'forceRunTask', $id, __('Invalid Task'), $this->response->type());
            }
            $this->Flash->error(__('Invalid Task'));
            $this->redirect(['action' => 'index']);
            return;
        }

        if ($task['Task']['enabled'] === false) {
            if ($this->IndexFilter->isRest()) {
                return $this->RestResponse->saveFailResponse('Task', 'forceRunTask', $id, __('Task is not enabled, cannot force run.'), $this->response->type());
            }
            $this->Flash->error(__('Task is not enabled, cannot force run.'));
            $this->redirect(['action' => 'index']);
            return;
        }

        if ($this->request->is('post')) {
            $task['Task']['next_execution_time'] = time() - 1;
            $task['Task']['last_job_id'] = null;

            $result = $this->Task->save($task);
            if ($result) {
                if ($this->IndexFilter->isRest()) {
                    return $this->RestResponse->saveSuccessResponse('Task', 'forceRunTask', $id, $this->response->type());
                }
                $this->Flash->success(__('Task forced to run immediately.'));
                $this->redirect(['action' => 'index']);
                return;
            } else {
                if ($this->IndexFilter->isRest()) {
                    return $this->RestResponse->saveFailResponse('Task', 'forceRunTask', $id, $this->validationError, $this->response->type());
                }
                $this->Flash->error(__('Failed to force run task: '));
                $this->redirect(['action' => 'index']);
                return;
            }
        } else {
            $this->set('task', $task);
            $this->layout = false;
            $this->render('ajax/force_run');
        }
    }

    public function viewLogs($id)
    {
        if (!$this->_isSiteAdmin()) {
            throw new MethodNotAllowedException('You are not authorised to do that.');
        }

        $task = $this->Task->find('first', array(
            'recursive' => -1,
            'conditions' => array('Task.id' => $id),
            'contain' => ['Job']
        ));

        if (empty($task)) {
            if ($this->IndexFilter->isRest()) {
                return $this->RestResponse->saveFailResponse('Task', 'viewTaskLogs', $id, __('Invalid Task'), $this->response->type());
            }
            $this->Flash->error(__('Invalid Task'));
            $this->redirect(['action' => 'index']);
            return;
        }

        if (empty($task['Job'])) {
            if ($this->IndexFilter->isRest()) {
                return $this->RestResponse->saveFailResponse('Task', 'viewTaskLogs', $id, __('No job found for this task'), $this->response->type());
            }
            $this->Flash->error(__('No job found for this task'));
            $this->redirect(['action' => 'index']);
            return;
        }

        $this->Org = ClassRegistry::init('Organisation');
        if (empty($task['Job']['org_id'])) {
            $task['Org'] = ['name' => 'ADMIN'];
        } else {
            $task['Org'] = $this->Org->find('first', [
                'conditions' => ['Organisation.id' => $task['Job']['org_id']],
                'fields' => ['Organisation.name'],
                'recursive' => -1
            ]);
        }

        $this->set('task', $task);
        $this->set('logs', $this->__getFailedJobLog($task['Job']['process_id']));
        $this->layout = false;
        $this->render('ajax/view_logs');
    }

    private function __getFailedJobLog(string $id): array
    {
        $job = $this->Task->getBackgroundJobsTool()->getJob($id);
        $output = $job ? $job->output() : __('Job status not found.');
        $backtrace = $job ? explode("\n", $job->error()) : [];

        return [
            'error' => $output ?? $backtrace[0] ?? '',
            'backtrace' => $backtrace
        ];
    }

    private function __getDropdownData()
    {
        $this->Server = ClassRegistry::init('Server');
        $this->Feed = ClassRegistry::init('Feed');
        $this->Workflow = ClassRegistry::init('Workflow');

        $workflows = $this->Workflow->find('all', [
            'order' => ['Workflow.name' => 'ASC'],
        ]);

        // Filter enabled workflows to only include those that have ad-hoc triggers
        $dropdownWorkflows = [];
        foreach ($workflows as $workflow) {
            if ($workflow['Workflow']['enabled']) {
                foreach ($workflow['Workflow']['listening_triggers'] as $listeningTrigger) {
                    if ($listeningTrigger['is_adhoc']) {
                        $dropdownWorkflows[$workflow['Workflow']['id']] = $workflow['Workflow']['name'];
                        break;
                    }
                }
            }
        }

        $dropdownData = [
            'users' => $this->User->find('list', [
                'fields' => ['User.id', 'User.email'],
                'conditions' => [
                    'User.disabled' => 0,
                    'User.org_id' => $this->Auth->user('org_id')
                ],
                'order' => ['User.email' => 'ASC']
            ]),
            'servers' =>  ['all' => __('All Servers')] + $this->Server->find('list', [
                'fields' => ['Server.id', 'Server.name'],
                'order' => ['Server.name' => 'ASC']
            ]),
            'feeds' => ['all' => __('All Feeds')] + $this->Feed->find('list', [
                'fields' => ['Feed.id', 'Feed.name'],
                'order' => ['Feed.name' => 'ASC']
            ]),
            'workflows' => $dropdownWorkflows,
        ];

        return $dropdownData;
    }

    private function __massageFormInput(array $data)
    {
        if ($data['Task']['type'] === 'Server') {
            $data['Task']['action'] = $data['Task']['server_action'];
            $data['Task']['params'] = implode(
                ',',
                [
                    $data['Task']['server_id'],
                    $data['Task']['server_technique']
                ]
            );
        } elseif ($data['Task']['type'] === 'Feed') {
            $data['Task']['action'] = $data['Task']['feed_action'];

            if ($data['Task']['feed_action'] === 'fetch') {
                if (!isset($data['Task']['feed_id']) || empty($data['Task']['feed_id'])) {
                    $this->Flash->error(__('Please select a feed.'));
                    return;
                }
                $data['Task']['params'] = $data['Task']['feed_id'];
            } elseif ($data['Task']['feed_action'] === 'cache') {
                if (!isset($data['Task']['feed_scope']) || empty($data['Task']['feed_scope'])) {
                    $this->Flash->error(__('Please select a feed scope.'));
                    return;
                }
                if ($data['Task']['feed_id'] === 'all') {

                    $data['Task']['params'] = implode(
                        ',',
                        [
                            $data['Task']['feed_id'],
                            $data['Task']['feed_scope'],
                        ]
                    );
                } else {
                    $data['Task']['params'] = $data['Task']['feed_id'];
                }
            } else {
                $this->Flash->error(__('Invalid action for Feed'));
                return;
            }
        } elseif ($data['Task']['type'] === 'Workflow') {
            $data['Task']['action'] = 'execute';

            if (!isset($data['Task']['workflow']) || empty($data['Task']['workflow'])) {
                $this->Flash->error(__('Please select a workflow.'));
                return;
            }
            $data['Task']['params'] = $data['Task']['workflow'];
        } elseif ($data['Task']['type'] === 'Periodic Summary') {
            $data['Task']['action'] = 'send';
        } elseif ($data['Task']['type'] === 'Admin') {
            $data['Task']['action'] = $data['Task']['admin_action'];

            if (!isset($data['Task']['admin_action']) || empty($data['Task']['admin_action'])) {
                $this->Flash->error(__('Please select an admin action.'));
                return;
            }

            if (!in_array($data['Task']['admin_action'], SchedulerWorkerShell::ADMIN_ACTIONS)) {
                $this->Flash->error(__('Invalid admin action selected.'));
                return;
            }
        } else {
            $this->Flash->error(__('Invalid type'));
            return;
        }

        $data['Task']['timer'] = $data['Task']['time_multiplier'] * $data['Task']['time_unit'];

        if ($data['Task']['timer'] < 60) {
            $this->Flash->error(__('Invalid timer value, must be at least 60 seconds or 1 minute.'));
            return;
        }

        if ($data['Task']['next_execution_date']) {
            $time = $data['Task']['next_execution_time'] == "" ? '00:00:00' : $data['Task']['next_execution_time'];
            $data['Task']['next_execution_time'] = strtotime($data['Task']['next_execution_date'] . ' ' . $time);
        } else {
            $data['Task']['next_execution_time'] = time() - 1;
        }

        return $data;
    }
}
