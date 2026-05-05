<?php
App::uses('AppController', 'Controller');

/**
 * @property Allowedlist $Allowedlist
 */
class AllowedlistsController extends AppController
{
    public $components = [
        'CRUD',
        'RequestHandler'
    ];

    public $paginate = [
        'limit' => 60,
        'order' => [
            'Allowedlist.name' => 'ASC'
        ]
    ];

    public function admin_add()
    {
        $this->CRUD->add();
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        if($this->theme === "Overmind"){
            $this->layout = false;
        }
        $this->set('action', 'add');
    }

    public function admin_index()
    {
        $params = [
            'filters' => ['name'],
            'quickFilters' => ['name']
        ];
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('list', $this->viewVars['data']);
        $this->render('index');
    }

    public function admin_edit($id = null)
    {
        $this->CRUD->edit($id);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        if($this->theme === "Overmind"){
            $this->layout = false;
        }
        $this->set('action', 'edit');
        $this->set('id', $id);
        $this->render('admin_add');
    }

    public function admin_delete($id = null)
    {
        $this->CRUD->delete($id);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function admin_deleteSelection($id = null)
    {
        return $this->CRUD->deleteSelection($id, [
            'modelName' => 'Allowedlist',
            'restName' => 'Allowedlists',
            'itemName' => 'allowedlist',
            'view' => 'ajax/allowedlistDeleteConfirmationForm',
            'checkModifyCallback' => function() {
                return $this->userRole['perm_regexp_access'];
            },
            'multiSuccessMessageCallback' => function($count) {
                return __n('%s allowedlist deleted.', '%s allowedlists deleted.', $count, $count);
            }
        ]);
    }


    public function index()
    {
        $params = [
            'filters' => ['name'],
            'quickFilters' => ['name']
        ];
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('list', $this->viewVars['data']);
    }
}
