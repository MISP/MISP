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
        $attachTarget = $this->__getAttachTargetFromRequest();
        $attachElementType = $attachTarget['type'] ?? null;
        $attachElementUuids = $attachTarget['uuids'] ?? [];
        $attachElementUuid = !empty($attachElementUuids) ? $attachElementUuids[0] : null;
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
                'afterSave' => function (array $collection) use ($attachTarget) {
                    $this->Collection->CollectionElement->captureElements($collection);
                    if ($attachTarget !== null) {
                        foreach ($attachTarget['uuids'] as $attachElementUuid) {
                            $this->__attachElementToCollection(
                                $collection['Collection']['id'],
                                $attachTarget['type'],
                                $attachElementUuid
                            );
                        }
                    }
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
        $this->set(compact('dropdownData', 'attachElementType', 'attachElementUuid', 'attachElementUuids'));
        if($this->theme === "Overmind"){
            $this->layout = false;
        }
        $this->render('add');
    }

    private function __getAttachTargetFromRequest()
    {
        $attachElementType = null;
        $attachElementUuids = [];

        if ($this->request->is('post')) {
            if (!empty($this->request->data['Collection']['_attach_element_type'])) {
                $attachElementType = $this->request->data['Collection']['_attach_element_type'];
            }
            if (!empty($this->request->data['Collection']['_attach_element_uuid'])) {
                $attachElementUuids = (array)$this->request->data['Collection']['_attach_element_uuid'];
            }
        }

        if (empty($attachElementType)) {
            $attachElementType = $this->request->query('attach_element_type');
        }
        if (empty($attachElementType) && !empty($this->request->params['named']['attach_element_type'])) {
            $attachElementType = $this->request->params['named']['attach_element_type'];
        }

        if (empty($attachElementUuids)) {
            $queryAttachElementUuid = $this->request->query('attach_element_uuid');
            if ($queryAttachElementUuid !== null) {
                $attachElementUuids = (array)$queryAttachElementUuid;
            }
        }
        if (empty($attachElementUuids) && !empty($this->request->params['named']['attach_element_uuid'])) {
            $attachElementUuids = (array)$this->request->params['named']['attach_element_uuid'];
        }

        $attachElementUuids = array_values(array_unique(array_filter(array_map(function ($uuid) {
            return is_scalar($uuid) ? trim((string)$uuid) : '';
        }, $attachElementUuids))));

        if (empty($attachElementType) && empty($attachElementUuids)) {
            return null;
        }
        if (empty($attachElementType) || empty($attachElementUuids)) {
            throw new BadRequestException(__('Incomplete collection attachment target.'));
        }
        if (!in_array($attachElementType, $this->Collection->CollectionElement->valid_types, true)) {
            throw new BadRequestException(__('Invalid element type for collection attachment.'));
        }
        foreach ($attachElementUuids as $attachElementUuid) {
            if (!Validation::uuid($attachElementUuid)) {
                throw new BadRequestException(__('Invalid element UUID for collection attachment.'));
            }
        }

        return [
            'type' => $attachElementType,
            'uuid' => $attachElementUuids[0],
            'uuids' => $attachElementUuids,
        ];
    }

    private function __attachElementToCollection($collectionId, $elementType, $elementUuid)
    {
        $this->Collection->CollectionElement->create();
        try {
            $this->Collection->CollectionElement->save([
                'CollectionElement' => [
                    'collection_id' => $collectionId,
                    'element_type' => $elementType,
                    'element_uuid' => $elementUuid,
                    'description' => ''
                ]
            ]);
        } catch (PDOException $e) {
            // Collection create can be retried safely; ignore duplicate attachment rows.
            if (empty($e->errorInfo[0]) || $e->errorInfo[0] != 23000) {
                throw $e;
            }
        }
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

    public function deleteSelection($id = null)
    {
        return $this->CRUD->deleteSelection($id, [
            'modelName' => 'Collection',
            'restName' => 'Collections',
            'itemName' => 'collection',
            'view' => 'ajax/collectionDeleteConfirmationForm',
            'checkModifyCallback' => function($itemId) {
                return $this->Collection->mayModify($this->Auth->user('id'), $itemId);
            },
            'multiSuccessMessageCallback' => function($count) {
                return __n('%s collection deleted.', '%s collections deleted.', $count, $count);
            }
        ]);
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
        $data = $this->viewVars['data'];
        $elements = $data['Collection']['CollectionElement'] ?? [];

        // Enrich elements with a human-readable reference so the elements
        // index can display the resolved target instead of the raw UUID.
        $eventUuids = [];
        $clusterUuids = [];
        foreach ($elements as $element) {
            $elementType = $element['element_type'] ?? null;
            if (empty($element['element_uuid'])) {
                continue;
            }
            if ($elementType === 'Event') {
                $eventUuids[] = $element['element_uuid'];
            } elseif ($elementType === 'GalaxyCluster') {
                $clusterUuids[] = $element['element_uuid'];
            }
        }

        $eventsByUuid = [];
        if (!empty($eventUuids)) {
            $this->loadModel('Event');
            $events = $this->Event->fetchSimpleEvents($user, [
                'conditions' => ['Event.uuid' => array_values(array_unique($eventUuids))]
            ]);
            foreach ($events as $event) {
                $eventsByUuid[$event['Event']['uuid']] = [
                    'id' => $event['Event']['id'],
                    'info' => $event['Event']['info'],
                ];
            }
        }

        $clustersByUuid = [];
        if (!empty($clusterUuids)) {
            $this->loadModel('GalaxyCluster');
            $clusters = $this->GalaxyCluster->fetchGalaxyClusters($user, [
                'conditions' => ['GalaxyCluster.uuid' => array_values(array_unique($clusterUuids))]
            ]);
            foreach ($clusters as $cluster) {
                $arranged = $this->GalaxyCluster->arrangeData($cluster);
                $clustersByUuid[$cluster['GalaxyCluster']['uuid']] = $arranged['GalaxyCluster'];
            }
        }

        if (!empty($eventsByUuid) || !empty($clustersByUuid)) {
            foreach ($elements as $k => $element) {
                $elementType = $element['element_type'] ?? null;
                $elementUuid = $element['element_uuid'] ?? null;
                if ($elementType === 'Event' && isset($eventsByUuid[$elementUuid])) {
                    $elements[$k]['Event'] = $eventsByUuid[$elementUuid];
                } elseif ($elementType === 'GalaxyCluster' && isset($clustersByUuid[$elementUuid])) {
                    $elements[$k]['GalaxyCluster'] = [$clustersByUuid[$elementUuid]];
                }
            }
            $data['Collection']['CollectionElement'] = $elements;
            $this->set('data', $data);
        }

        $totalElements = count($elements);
        $this->request->params['paging']['CollectionElement'] = [
            'page'      => 1,
            'current'   => $totalElements,
            'count'     => $totalElements,
            'prevPage'  => false,
            'nextPage'  => false,
            'pageCount' => 1,
            'order'     => null,
            'limit'     => 50,
            'options'   => [],
            'paramType' => 'named',
        ];

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

    /**
     * Returns the collections that contain a given element (by type + uuid).
     * Read-only, JSON only. Used by the beta UI event view widget.
     *
     * GET /collections/getCollectionsForElement/Event/<uuid>.json
     */
    public function getCollectionsForElement($element_type, $element_uuid)
    {
        if (!$this->_isRest()) {
            throw new MethodNotAllowedException(__('This endpoint is JSON only.'));
        }
        $result = $this->__getCollectionsByElementUuids($element_type, [$element_uuid]);
        return $this->RestResponse->viewData($result[$element_uuid], $this->response->type());
    }

    /**
     * Returns the collections for multiple elements of the same type.
     * Read-only, JSON only. Response is keyed by element UUID to keep
     * existing single-element consumers untouched while allowing batching.
     *
     * POST /collections/getCollectionsForElements/Event.json
     * {"uuids": ["<uuid>", "<uuid>"]}
     */
    public function getCollectionsForElements($element_type)
    {
        if (!$this->_isRest()) {
            throw new MethodNotAllowedException(__('This endpoint is JSON only.'));
        }
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('This endpoint only accepts POST requests.'));
        }

        $requestData = $this->request->input('json_decode', true);
        $uuids = [];
        if (!empty($this->request->data['uuids']) && is_array($this->request->data['uuids'])) {
            $uuids = $this->request->data['uuids'];
        } elseif (!empty($requestData['uuids']) && is_array($requestData['uuids'])) {
            $uuids = $requestData['uuids'];
        }
        $uuids = array_values(array_unique(array_filter($uuids)));
        if (empty($uuids)) {
            return $this->RestResponse->viewData([], $this->response->type());
        }

        $result = $this->__getCollectionsByElementUuids($element_type, $uuids);
        return $this->RestResponse->viewData($result, $this->response->type());
    }

    private function __getCollectionsByElementUuids($elementType, array $uuids)
    {
        $uuids = array_values(array_unique(array_filter($uuids)));
        if (empty($uuids)) {
            return [];
        }

        $this->loadModel('CollectionElement');
        $elements = $this->CollectionElement->find('all', [
            'recursive' => -1,
            'conditions' => [
                'CollectionElement.element_type' => $elementType,
                'CollectionElement.element_uuid' => $uuids
            ],
            'fields' => ['CollectionElement.collection_id', 'CollectionElement.element_uuid']
        ]);

        $result = array_fill_keys($uuids, []);
        if (empty($elements)) {
            return $result;
        }

        $collectionIds = array_values(array_unique(array_column(array_column($elements, 'CollectionElement'), 'collection_id')));
        $userId = $this->Auth->user('id');
        $conditions = ['Collection.id' => $collectionIds];
        if (!$this->_isSiteAdmin()) {
            $conditions['AND'][] = $this->Collection->buildConditions($userId);
        }
        $collections = $this->Collection->find('all', [
            'recursive' => -1,
            'conditions' => $conditions,
            'fields' => ['Collection.id', 'Collection.name', 'Collection.type', 'Collection.description', 'Collection.uuid']
        ]);

        $collectionsById = [];
        foreach ($collections as $collection) {
            $collectionsById[$collection['Collection']['id']] = $collection['Collection'];
        }

        foreach ($elements as $element) {
            $collectionId = $element['CollectionElement']['collection_id'];
            $elementUuid = $element['CollectionElement']['element_uuid'];
            if (!isset($collectionsById[$collectionId])) {
                continue;
            }
            $result[$elementUuid][] = $collectionsById[$collectionId];
        }

        return $result;
    }
}
