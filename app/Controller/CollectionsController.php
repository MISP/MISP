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
        'research',
        'other'
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
        if($this->theme === "Overmind"){
            $this->layout = false;
        }
        $this->render('add');
    }

    public function edit($id)
    {
        $id = $this->Toolbox->findIdByUuid($this->Collection, $id);
        $this->Collection->current_user = $this->Auth->user();
        if (!$this->Collection->mayModify($this->Auth->user('id'), $id)) {
            throw new MethodNotAllowedException(__('Invalid Collection or insufficient privileges'));
        }
        $params = [];
        $this->loadModel('Event');
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
            if (isset($data['Collection']['distribution']) && $data['Collection']['distribution'] == 4) {
                $canSGBeUsed = $this->Event->SharingGroup->checkIfCanBeUsed($this->Auth->user(), $this->_isRest(), $data, 'Collection');
                if ($canSGBeUsed !== true) {
                    throw new MethodNotAllowedException($canSGBeUsed);
                }
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
        $dropdownData = [
            'types' => array_combine($this->valid_types, $this->valid_types),
            'distributionLevels' => $this->Event->distributionLevels,
            'sgs' => $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1)  
        ];
        $this->set(compact('dropdownData'));
        if($this->theme === "Overmind"){
            $this->layout = false;
        }
        $this->render('add');
    }

    public function delete($id)
    {
        $id = $this->Toolbox->findIdByUuid($this->Collection, $id);
        if (!$this->Collection->mayModify($this->Auth->user('id'), $id)) {
            throw new MethodNotAllowedException(__('Invalid Collection or insufficient privileges'));
        }
        $this->CRUD->delete($id);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function delete2($id = null)
    {
        if ($this->request->is(['post', 'put', 'delete'])) {
            if (isset($this->request->data['id'])) {
                $this->request->data['Collection'] = $this->request->data;
            }
            if (!isset($id) && isset($this->request->data['Collection']['id'])) {
                $idList = $this->request->data['Collection']['id'];

                if (!is_array($idList)) {
                    if (is_numeric($idList) || Validation::uuid($idList)) {
                        $idList = array($idList);
                    } else {
                        $idList = $this->_jsonDecode($idList);
                    }
                }

                if (empty($idList)) {
                    throw new NotFoundException(__('Invalid input.'));
                }
            } else {
                $idList = array($id);
            }

            $successes = [];
            $fails = [];
            foreach ($idList as $cid) {
                $collection = $this->Collection->find('first', [
                    'conditions' => Validation::uuid($cid)
                        ? ['Collection.uuid' => $cid]
                        : ['Collection.id' => $cid],
                    'recursive' => -1,
                ]);
                if (empty($collection)) {
                    $fails[] = $cid;
                    continue;
                }
                $collectionId = $collection['Collection']['id'];
                if (!$this->Collection->mayModify($this->Auth->user('id'), $collectionId)) {
                    $fails[] = $cid;
                    continue;
                }
                if ($this->Collection->delete($collectionId)) {
                    $successes[] = $cid;
                } else {
                    $fails[] = $cid;
                }
            }
            if (count($idList) === 1) {
                $message = empty($successes)
                    ? __('Collection was not deleted.')
                    : __('Collection deleted.');
            } else {
                $message = '';
                if (!empty($successes)) {
                    $message .= __n(
                        '%s collection deleted.',
                        '%s collections deleted.',
                        count($successes),
                        count($successes)
                    );
                }
                if (!empty($fails)) {
                    $message .= ' ' . count($fails) . ' collection(s) could not be deleted due to insufficient privileges or not found.';
                }
            }
            if ($this->_isRest()) {
                if (!empty($successes)) {
                    return $this->RestResponse->saveSuccessResponse(
                        'Collections',
                        'delete',
                        $id,
                        $this->response->type(),
                        $message
                    );
                } else {
                    return $this->RestResponse->saveFailResponse(
                        'Collections',
                        'delete',
                        false,
                        $message,
                        $this->response->type()
                    );
                }
            }
            if (!empty($successes)) {
                $this->Flash->success($message);
            } else {
                $this->Flash->error($message);
            }
            return $this->redirect(['action' => 'index']);
        } else {
            $collectionList = is_numeric($id) ? [$id] : $this->_jsonDecode($id);
            $this->request->data['Collection']['id'] = json_encode($collectionList);
            $this->set('idArray', $collectionList);
            $this->layout = false;
            $this->render('ajax/collectionDeleteConfirmationForm');
        }
    }

    public function view($id)
    {
        $id = $this->Toolbox->findIdByUuid($this->Collection, $id);
        $this->set('mayModify', $this->Collection->mayModify($this->Auth->user('id'), $id));
        if (!$this->Collection->mayView($this->Auth->user('id'), $id)) {
            throw new MethodNotAllowedException(__('Invalid Collection or insufficient privileges'));
        }
        $this->set('menuData', array('menuList' => 'collections', 'menuItem' => 'view'));
        $user = $this->Auth->user();
        $params = [
            'contain' => [
                'Orgc',
                'Org',
                'User',
                'CollectionElement'
            ],
            'afterFind' => function (array $collection) use ($user) {
                return $this->Collection->rearrangeCollection($collection, $user);
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
