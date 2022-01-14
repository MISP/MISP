<?php
App::uses('AppController', 'Controller');

class TaxiiServersController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public function beforeFilter()
    {
        parent::beforeFilter();
    }

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999
    );

    public function index()
    {
        $params = [
            'filters' => ['name', 'url', 'uuid'],
            'quickFilters' => ['name']
        ];
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', array('menuList' => 'sync', 'menuItem' => 'list_taxii'));
    }

    public function add()
    {
        $params = [];
        $this->CRUD->add($params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
        $dropdownData = [];
        $this->set(compact('dropdownData'));
        $this->set('menuData', array('menuList' => 'sync', 'menuItem' => 'add_taxii'));
    }

    public function edit($id)
    {
        $this->set('menuData', array('menuList' => 'sync', 'menuItem' => 'edit_taxii'));
        $this->set('id', $id);
        $params = [];
        $this->CRUD->edit($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $dropdownData = [];
        $this->set(compact('dropdownData'));
        $this->render('add');
    }

    public function delete($id)
    {
        $this->CRUD->delete($id);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function view($id)
    {
        $this->set('menuData', ['menuList' => 'sync', 'menuItem' => 'view_taxii']);
        $this->CRUD->view($id);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('id', $id);
    }

    public function push($id)
    {
        $this->set('menuData', ['menuList' => 'sync', 'menuItem' => 'push_taxii']);
        $taxii_server = $this->TaxiiServer->find('first', [
            'recursive' => -1,
            'conditions' => ['TaxiiServer.id' => $id]
        ]);
        if (empty($taxii_server)) {
            throw new NotFoundException(__('Invalid Taxii Server ID provided.'));
        }

        if ($this->request->is('post')) {
            $result = $this->TaxiiServer->pushRouter($taxii_server['TaxiiServer']['id'],  $this->Auth->user());
            $message = __('Taxii push initiated.');
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('TaxiiServers', 'push', $id, false, $message);
            } else {
                $this->Flash->success($message);
                $this->redirect($this->referer());
            }
        } else {
            $this->set('id', $taxii_server['TaxiiServer']['id']);
            $this->set('title', __('Push data to TAXII server'));
            $this->set('question', __('Are you sure you want to Push data as configured in the filters to the TAXII server?'));
            $this->set('actionName', __('Push'));
            $this->layout = 'ajax';
            $this->render('/genericTemplates/confirm');
        }
    }
}
