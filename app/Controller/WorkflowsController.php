<?php
App::uses('AppController', 'Controller');

class WorkflowsController extends AppController
{
    public $components = array(
    );

    public function index()
    {
        $params = [
            'filters' => ['name', 'uuid'],
            'quickFilters' => ['name', 'uuid']
        ];
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', array('menuList' => 'workflows', 'menuItem' => 'index'));
    }

    public function add()
    {
        $currentUser = $this->Auth->user();
        $params = [
            'beforeSave' => function ($data) use ($currentUser) {
                $data['Workflow']['uuid'] = CakeText::uuid();
                $data['Workflow']['user_id'] = $currentUser['id'];
                $data['Workflow']['org_id'] = $currentUser['org_id'];
                if (!isset($data['Workflow']['description'])) {
                    $data['Workflow']['description'] = '';
                }
                if (empty($data['Workflow']['data'])) {
                    $data['Workflow']['data'] = '{}';
                }
                return $data;
            },
            'redirect' => [
                'action' => 'index',
            ]
        ];
        $this->CRUD->add($params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', array('menuList' => 'workflows', 'menuItem' => 'add'));
    }

    public function edit($id)
    {
        $this->set('id', $id);
        $params = [
            'fields' => ['name', 'description', 'data'],
            'redirect' => [
                'action' => 'index',
            ]
        ];
        $workflow = $this->Workflow->fetchWorkflow($this->Auth->user(), $id);
        if (empty($workflow)) {
            throw new NotFoundException(__('Invalid workflow'));
        }
        $this->CRUD->edit($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }

        $this->set('menuData', array('menuList' => 'workflows', 'menuItem' => 'edit'));
        $this->render('add');
    }

    public function delete($id)
    {
        $params = [
            'redirect' => [
                'action' => 'index',
            ]
        ];
        $this->CRUD->delete($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function view($id)
    {
        $this->CRUD->view($id, [
            'contain' => ['Organisation', 'User']
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('id', $id);
        $this->set('menuData', array('menuList' => 'workflows', 'menuItem' => 'view'));
    }

    public function editor()
    {
        $modules = $this->Workflow->getModules();
        $this->set('modules', $modules);
    }

    private function __getSuccessResponseBasedOnContext($message, $data = null, $action = '', $id = false, $redirect = array())
    {
        if ($this->_isRest()) {
            if (!is_null($data)) {
                return $this->RestResponse->viewData($data, $this->response->type());
            } else {
                return $this->RestResponse->saveSuccessResponse($this->EventReport->alias, $action, $id, false, $message);
            }
        } elseif ($this->request->is('ajax')) {
            return $this->RestResponse->saveSuccessResponse($this->EventReport->alias, $action, $id, false, $message, $data);
        } else {
            $this->Flash->success($message);
            $this->redirect($redirect);
        }
        return;
    }

    private function __getFailResponseBasedOnContext($message, $data = null, $action = '', $id = false, $redirect = array())
    {
        if (is_array($message)) {
            $message = implode(', ', $message);
        }
        if ($this->_isRest()) {
            if ($data !== null) {
                return $this->RestResponse->viewData($data, $this->response->type());
            } else {
                return $this->RestResponse->saveFailResponse('EventReport', $action, $id, $message);
            }
        } elseif ($this->request->is('ajax')) {
            return $this->RestResponse->saveFailResponse('EventReport', $action, $id, $message, false, $data);
        } else {
            $this->Flash->error($message);
            $this->redirect($this->referer());
        }
    }
}
