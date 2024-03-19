<?php
App::uses('AppController', 'Controller');

class CollectionsController extends AppController
{

    public $components = ['Session', 'RequestHandler'];

    public $paginate = [
        'limit' => 60,
        'order' => []
    ];

    public $uses = [
    ];

    private $valid_types = [
        'campaign',
        'intrusion_set',
        'named_threat',
        'other',
        'research'
    ];
    
    public function add()
    {   
        $this->Collection->current_user = $this->Auth->user();
        $params = [];
        if ($this->request->is('post')) {
            $data = $this->request->data;
            $params = [
                'afterSave' => function (array $collection) use ($data) {
                    $this->Collection->CollectionElement->captureElements($collection);
                    return $collection;
                }
            ];
        }
        $this->CRUD->add($params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', array('menuList' => 'collections', 'menuItem' => 'add'));
        $this->loadModel('Event');
        $dropdownData = [
            'types' => array_combine($this->valid_types, $this->valid_types),
            'distributionLevels' => $this->Event->distributionLevels,
            'sgs' => $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1)  
        ];
        $this->set('initialDistribution', Configure::read('MISP.default_event_distribution'));
        $this->set(compact('dropdownData'));
        $this->render('add');
    }

    public function edit($id)
    {
        $this->Collection->current_user = $this->Auth->user();
        if (!$this->Collection->mayModify($this->Auth->user('id'), $id)) {
            throw new MethodNotAllowedException(__('Invalid Collection or insuficient privileges'));
        }
        $params = [];
        if ($this->request->is('post') || $this->request->is('put')) {
            $oldCollection = $this->Collection->find('first', [
                'recursive' => -1,
                'conditions' => ['Collection.id' => intval($id)]
            ]);
            if (empty($oldCollection)) {
                throw new NotFoundException(__('Invalid collection.'));
            }
            if (empty($this->request->data['Collection'])) {
                $this->request->data = ['Collection' => $this->request->data];
            }
            $data = $this->request->data;
            if (
                isset($data['Collection']['modified']) &&
                $data['Collection']['modified'] <= $oldCollection['Collection']['modified']
            ) {
                throw new ForbiddenException(__('Collection received older or same as local version.'));
            }
            $params = [
                'afterSave' => function (array &$collection) use ($data) {
                    $collection = $this->Collection->CollectionElement->captureElements($collection);
                    return $collection;
                }
            ];
        }
        $this->set('id', $id);
        $this->CRUD->edit($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', array('menuList' => 'collections', 'menuItem' => 'edit'));
        $this->loadModel('Event');
        $dropdownData = [
            'types' => $this->valid_types,
            'distributionLevels' => $this->Event->distributionLevels,
            'sgs' => $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1)  
        ];
        $this->set(compact('dropdownData'));
        $this->render('add');
    }

    public function delete($id)
    {
        if (!$this->Collection->mayModify($this->Auth->user('id'), $id)) {
            throw new MethodNotAllowedException(__('Invalid Collection or insuficient privileges'));
        }
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
        $this->set('menuData', array('menuList' => 'collections', 'menuItem' => 'view'));
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
        $this->set('menuData', array('menuList' => 'collections', 'menuItem' => 'index'));
        $params = [
            'filters' => ['Collection.uuid', 'Collection.type', 'Collection.name'],
            'quickFilters' => ['Collection.name'],
            'contain' => ['Orgc'],
            'afterFind' => function($collections) {
                foreach ($collections as $k => $collection) {
                    $collections[$k]['Collection']['element_count'] = $this->Collection->CollectionElement->find('count', [
                        'recursive' => -1,
                        'conditions' => ['CollectionElement.collection_id' => $collection['Collection']['id']]
                    ]);
                }
                return $collections;
            }
        ];
        if ($filter === 'my_collections') {
            $params['conditions']['Collection.user_id'] = $this->Auth->user('id');
        }
        if ($filter === 'org_collections') {
            $params['conditions']['Collection.orgc_id'] = $this->Auth->user('org_id');
        }
        $this->loadModel('Event');
        $this->set('distributionLevels', $this->Event->distributionLevels);
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }
}
