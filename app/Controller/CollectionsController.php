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
        $currentUser = $this->Auth->user();
        $params = [];
        $this->loadModel('Event');
        if ($this->request->is('post')) {
            $data = $this->request->data;
            $params = [
                'beforeSave' => function (array $collection) use ($currentUser) {
                    if (isset($collection['Collection']['distribution']) && $collection['Collection']['distribution'] == 4) {
                        $canSGBeUsed = $this->Event->SharingGroup->checkIfCanBeUsed($currentUser, $this->_isRest(), $collection, 'Collection');
                        if ($canSGBeUsed !== true) {
                            throw new MethodNotAllowedException($canSGBeUsed);
                        }
                    }
                    return $collection;
                },
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
        $id = $this->Toolbox->findIdByUuid($this->Collection, $id);
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
            // The sharing-group authorisation check must run against the EFFECTIVE distribution
            // and sharing group after the edit, not only when 'distribution' is present in the
            // body. CRUDComponent::edit() retains the stored value for any field the request
            // omits, so a user could retarget an existing distribution=4 collection onto a
            // sharing group they are not authorised to use simply by omitting 'distribution'
            // (it stays 4 from the stored record) while mass-assigning sharing_group_id. Validate
            // whenever the effective distribution is 4 and this request actually changes the
            // distribution or the sharing group (an untouched SG on an unrelated edit is left
            // as-is so a legitimate owner can still edit other fields).
            $effectiveDistribution = isset($data['Collection']['distribution'])
                ? $data['Collection']['distribution']
                : $oldCollection['Collection']['distribution'];
            $sgChanged = isset($data['Collection']['sharing_group_id'])
                && $data['Collection']['sharing_group_id'] != $oldCollection['Collection']['sharing_group_id'];
            $distChanged = isset($data['Collection']['distribution'])
                && $data['Collection']['distribution'] != $oldCollection['Collection']['distribution'];
            if ($effectiveDistribution == 4 && ($sgChanged || $distChanged)) {
                $sgCheckData = $data;
                if (!isset($sgCheckData['Collection']['sharing_group_id'])) {
                    $sgCheckData['Collection']['sharing_group_id'] = $oldCollection['Collection']['sharing_group_id'];
                }
                $canSGBeUsed = $this->Event->SharingGroup->checkIfCanBeUsed($this->Auth->user(), $this->_isRest(), $sgCheckData, 'Collection');
                if ($canSGBeUsed !== true) {
                    throw new MethodNotAllowedException($canSGBeUsed);
                }
            }
            $params = [
                // Identity and ownership fields must never be reassigned through edit. The model only
                // forces these on create (Collection::beforeValidate runs its ownership block only when
                // the id is empty), and CRUDComponent::edit() copies every supplied field onto the loaded
                // record. Without pinning them here a user could hand the collection to another org/user,
                // or redirect the save onto a different collection via an injected id (mayModify only
                // checked the id from the route). Force them back to the stored values.
                'override' => [
                    'id' => $oldCollection['Collection']['id'],
                    'orgc_id' => $oldCollection['Collection']['orgc_id'],
                    'org_id' => $oldCollection['Collection']['org_id'],
                    'user_id' => $oldCollection['Collection']['user_id'],
                ],
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
            'types' => array_combine($this->valid_types, $this->valid_types),
            'distributionLevels' => $this->Event->distributionLevels,
            'sgs' => $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1)  
        ];
        $this->set(compact('dropdownData'));
        $this->render('add');
    }

    public function delete($id)
    {
        $id = $this->Toolbox->findIdByUuid($this->Collection, $id);
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
        $id = $this->Toolbox->findIdByUuid($this->Collection, $id);
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
            'contain' => ['Orgc', 'SharingGroup'],
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
        if (!$this->_isSiteAdmin()) {
            $params['conditions']['AND'][] = $this->Collection->buildConditions($this->Auth->user('id'));
        }
        $this->loadModel('Event');
        $this->set('distributionLevels', $this->Event->distributionLevels);
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }
}
