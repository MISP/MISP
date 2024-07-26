<?php
App::uses('AppController', 'Controller');

class CorrelationRulesController extends AppController
{

    public $components = ['Session', 'RequestHandler'];

    public $paginate = [
        'limit' => 60,
        'order' => []
    ];

    public $uses = [
    ];
    
    public function add()
    {   
        $params = [];
        $this->CRUD->add();
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', array('menuList' => 'correlationRules', 'menuItem' => 'add'));
        $dropdownData = [
            'selector_types' => $this->CorrelationRule->valid_types
        ];
        $this->set(compact('dropdownData'));
        $this->render('add');
    }

    public function edit($id)
    {
        $params = [];
        $this->set('id', $id);
        $this->CRUD->edit($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', array('menuList' => 'correlationRules', 'menuItem' => 'add'));
        $dropdownData = [
            'selector_types' => $this->CorrelationRule->valid_types
        ];
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
        $this->set('mayModify', $this->Collection->mayModify($this->Auth->user('id'), $id));
        if (!$this->Collection->mayView($this->Auth->user('id'), $id)) {
            throw new MethodNotAllowedException(__('Invalid Collection or insuficient privileges'));
        }
        $this->set('menuData', array('menuList' => 'correlationRules', 'menuItem' => 'view'));
        $params = [
            'contain' => [
                'Orgc',
                'Org',
                'User',
                'CollectionElement'
            ],
            'afterFind' => function (array $collection){
                return $this->Collection->rearrangeCollection($collection);
            }
        ];
        $this->CRUD->view($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('id', $id);
        $this->loadModel('Event');
        $this->set('distributionLevels', $this->Event->distributionLevels);
        $this->render('view');
    }

    public function index($filter = null)
    {
        $this->set('menuData', array('menuList' => 'correlationRules', 'menuItem' => 'index'));
        $params = [
            'filters' => ['uuid', 'name', 'selector_type'],
            'quickFilters' => ['name']
        ];
        $dropdownData = [
            'selector_types' => $this->CorrelationRule->valid_types
        ];
        $this->set(compact('dropdownData'));
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }
}
