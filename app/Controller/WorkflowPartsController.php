<?php
App::uses('AppController', 'Controller');

class WorkflowPartsController extends AppController
{
    public $components = array(
        'RequestHandler'
    );

    public function index()
    {
        $params = [
            'filters' => ['name', 'uuid', 'timestamp'],
            'quickFilters' => ['name', 'uuid'],
        ];
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', ['menuList' => 'workflowParts', 'menuItem' => 'index']);
    }

    public function add($fromEditor = false)
    {
        $params = [];
        $this->CRUD->add($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('fromEditor', !empty($fromEditor));
        $this->set('menuData', ['menuList' => 'workflowParts', 'menuItem' => 'add']);
    }

    public function edit($id)
    {
        $params = [];
        $this->CRUD->edit($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', ['menuList' => 'workflowParts', 'menuItem' => 'edit']);
        $this->set('id', $id);
        $this->render('add');
    }

    public function delete($id)
    {
        $params = [
        ];
        $this->CRUD->delete($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', ['menuList' => 'workflowParts', 'menuItem' => 'delete']);
    }

    public function view($id)
    {
        $this->CRUD->view($id, [
        ]);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('id', $id);
        $this->set('menuData', ['menuList' => 'workflowParts', 'menuItem' => 'view']);
    }

    public function import()
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            $workflowPartData = JsonTool::decode($this->request->data['WorkflowPart']['data']);
            if ($workflowPartData === null) {
                throw new MethodNotAllowedException(__('Error while decoding JSON'));
            }
            $this->request->data['WorkflowPart']['data'] = JsonTool::encode($workflowPartData);
            $this->add();
        }
    }

    public function export($id)
    {
        $workflowPart = $this->WorkflowPart->find('first', [
            'conditions' => [
                'id' => $id,
            ]
        ]);
        $content = JsonTool::encode($workflowPart, JSON_PRETTY_PRINT);
        $this->response->body($content);
        $this->response->type('json');
        $this->response->download(sprintf('workflowpart_%s_%s.json', $workflowPart['WorkflowPart']['name'], time()));
        return $this->response;
    }
}
