<?php
App::uses('AppController', 'Controller');
App::uses('ActiveWorkspaceTool', 'Tools');
App::uses('AnalystData', 'Model');
App::uses('Collection', 'Model');
App::uses('CollectionRailCards', 'Tools/RailCards');
App::uses('SyncTool', 'Tools');

class CollectionsController extends AppController
{

    public $components = ['Session', 'RequestHandler'];

    public function beforeFilter()
    {
        parent::beforeFilter();
        // Posted by hand-built AJAX from the event and index collection panels
        // and by the workspace, which send the CSRF token as the X-CSRF-Token header;
        // publish's review form carries a choice of its own markup.
        $this->_csrfTokenHeaderOnly(['getCollectionsForElements', 'active', 'quickAdd', 'publish']);
        $this->Collection->CollectionElement->current_user = $this->Auth->user();
    }

    /**
     * Review and publish. GET: what the publish releases (the modal, or its
     * lists as JSON); POST {analysis?}: release it, saying how far the
     * investigation went.
     */
    public function publish($id)
    {
        $this->request->allowMethod(['get', 'post', 'put']);
        $user = $this->Auth->user();
        $id = $this->Toolbox->findIdByUuid($this->Collection, $id);
        $found = $this->Collection->find('first', [
            'recursive' => -1,
            'contain' => ['Orgc'],
            'conditions' => ['Collection.id' => $id],
        ]);
        if (empty($found) || !$this->Collection->mayView($user['id'], $id)) {
            throw new NotFoundException(__('Invalid collection.'));
        }
        $collection = $found['Collection'] + ['Orgc' => $found['Orgc']];
        if (!$this->Collection->canPublish($user, $collection)) {
            throw new ForbiddenException(__('Publishing “%s” takes the right to publish and to edit it.', $collection['name']));
        }
        if ((int)$collection['distribution'] === 0) {
            throw new BadRequestException(__('“%s” is shared with your organisation only: there is nothing to publish.', $collection['name']));
        }
        if ($this->request->is('get')) {
            $review = $this->Collection->publishReview($user, $collection);
            if ($this->_isRest()) {
                return $this->RestResponse->viewData(['Collection' => $this->__publishState($user, $id), 'review' => $review], 'json');
            }
            $who = array_filter(array_merge(
                Hash::extract($review['added']['items'], '{n}.user_id'),
                Hash::extract($review['removed']['items'], '{n}.user_id')
            ));
            $this->loadModel('User');
            $this->set('reviewers', empty($who) ? [] : $this->User->find('list', [
                'recursive' => -1,
                'fields' => ['User.id', 'User.email'],
                'conditions' => ['User.id' => array_values(array_unique($who))],
            ]));
            $this->set('collection', $collection);
            $this->set('publishState', $this->__publishState($user, $id));
            $this->set('review', $review);
            $this->layout = false;
            return $this->render('ajax/publishReview');
        }
        $input = $this->request->data['Collection'] ?? $this->request->data;
        $analysis = is_array($input) && isset($input['analysis']) && $input['analysis'] !== '' ? $input['analysis'] : null;
        if ($analysis !== null && (!is_numeric($analysis) || !in_array((int)$analysis, Collection::ANALYSIS_LEVELS, true))) {
            throw new BadRequestException(__('Say how far the investigation went: 0 Initial, 1 Ongoing or 2 Completed.'));
        }
        if (!$this->Collection->publish($id, $analysis === null ? null : (int)$analysis)) {
            return $this->RestResponse->saveFailResponse('Collections', 'publish', $id, $this->Collection->validationErrors, $this->response->type());
        }
        $message = __('“%s” is published: partners receive it, its members, graphs and links on the next synchronisation.', $collection['name']);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData(['Collection' => $this->__publishState($user, $id), 'message' => $message], 'json');
        }
        $this->Flash->success($message);
        return $this->redirect(['action' => 'view', $id]);
    }

    /**
     * @param array $user
     * @param int $id
     * @return array|null The collection as the workspace chip reads it
     */
    private function __publishState(array $user, $id)
    {
        return $this->Collection->workspaceSummaries($user, ['Collection.id' => (int)$id], 1)[0] ?? null;
    }

    /**
     * The user's workspace. POST {collection_uuid, graph_uuid?} makes a
     * collection they may edit their workspace, laid out by one of their
     * organisation's graphs on it, or by none when graph_uuid is null; left
     * out, the newest of them. A null collection ends it.
     */
    public function active()
    {
        $this->request->allowMethod(['get', 'post']);
        $user = $this->Auth->user();
        if ($this->request->is('get')) {
            return $this->RestResponse->viewData(ActiveWorkspaceTool::forUser($user), 'json');
        }
        $input = is_array($this->request->data) ? $this->request->data : [];
        $collection = array_key_exists('collection_uuid', $input) ? $input['collection_uuid'] : false;
        if ($collection === false || ($collection !== null && !is_string($collection))) {
            throw new BadRequestException(__('Name the collection to work in, or null for none.'));
        }
        $graph = $input['graph_uuid'] ?? null;
        if ($graph !== null && !is_string($graph)) {
            throw new BadRequestException(__('Name the graph by its uuid, or null for none.'));
        }
        list($workspace, $refusal) = ActiveWorkspaceTool::choose($user, $collection, $graph, array_key_exists('graph_uuid', $input));
        switch ($refusal) {
            case 'collection':
                throw new NotFoundException(__('Invalid collection.'));
            case 'edit':
                throw new ForbiddenException(__('Only a collection you can edit can be your workspace, and “%s” is not one.', $workspace['Collection']['name']));
            case 'graph':
                throw new BadRequestException(__('That graph is not one of your organisation’s graphs on “%s”.', $workspace['Collection']['name']));
        }
        return $this->RestResponse->viewData($workspace, 'json');
    }

    /**
     * New collection…: {name, type?, distribution?, sharing_group_id?,
     * description?, workspace?}. Research, for the organisation only, unless
     * the request says otherwise; with `workspace` true it becomes the
     * user's workspace in the same request.
     */
    public function quickAdd()
    {
        $this->request->allowMethod(['post']);
        $user = $this->Auth->user();
        $input = is_array($this->request->data) ? $this->request->data : [];
        if (!is_string($input['name'] ?? null)) {
            throw new BadRequestException(__('A collection needs a name.'));
        }
        $record = [
            'name' => trim($input['name']),
            'type' => is_string($input['type'] ?? null) ? $input['type'] : 'research',
            'distribution' => isset($input['distribution']) && is_scalar($input['distribution']) ? (string)$input['distribution'] : '0',
            'description' => is_string($input['description'] ?? null) ? $input['description'] : '',
        ];
        if ($record['distribution'] === '4') {
            $record['sharing_group_id'] = $input['sharing_group_id'] ?? null;
            $canUse = $this->Collection->SharingGroup->checkIfCanBeUsed($user, false, $record);
            if ($canUse !== true) {
                throw new MethodNotAllowedException($canUse);
            }
        }
        $this->Collection->current_user = $user;
        $this->Collection->create();
        if (!$this->Collection->save(['Collection' => $record])) {
            return $this->RestResponse->saveFailResponse('Collections', 'quickAdd', false, $this->Collection->validationErrors, 'json');
        }
        $collection = $this->Collection->workspaceSummaries($user, ['Collection.id' => $this->Collection->id], 1)[0] ?? null;
        $workspace = null;
        if (!empty($input['workspace']) && $collection !== null) {
            list($workspace) = ActiveWorkspaceTool::choose($user, $collection['uuid'], null);
        }
        return $this->RestResponse->viewData(['Collection' => $collection, 'workspace' => $workspace], 'json');
    }

    /**
     * The collections the user may make their workspace, the ones they used
     * last first; `?scope=mine` keeps those they created.
     */
    public function editable()
    {
        $this->request->allowMethod(['get']);
        $user = $this->Auth->user();
        $scope = ($this->request->query['scope'] ?? null) === 'mine' ? 'mine' : 'org';
        return $this->RestResponse->viewData([
            'Collection' => ActiveWorkspaceTool::editable($user, $scope),
            'active' => ActiveWorkspaceTool::stored($user),
        ], 'json');
    }

    public $paginate = [
        'limit' => 60,
        'order' => []
    ];

    public $uses = [
    ];

    public function add()
    {
        $this->Collection->current_user = $this->Auth->user();
        $currentUser = $this->Auth->user();
        $attachTarget = $this->__getAttachTargetFromRequest();
        $attachElementType = $attachTarget['type'] ?? null;
        $attachElementUuids = $attachTarget['uuids'] ?? [];
        // A value is shown by its text when the user can see it, never its SHA-256
        $attachElementLabels = $attachElementUuids;
        if (in_array($attachElementType, AnalystData::SHA256_TARGETS, true)) {
            $described = $this->Collection->CollectionElement->attachTargets($currentUser, array_map(function ($hex) use ($attachElementType) {
                return ['element_type' => $attachElementType, 'element_sha256' => $hex];
            }, $attachElementUuids));
            foreach ($described as $i => $element) {
                $attachElementLabels[$i] = $element[$attachElementType]['value'] ?? $attachElementUuids[$i];
            }
        }
        $attachElementUuid = !empty($attachElementUuids) ? $attachElementUuids[0] : null;
        $params = [];
        $this->loadModel('Event');
        // Accept PUT as well as POST: CRUDComponent::add() persists on either verb, so the
        // sharing-group authorisation check and element capture below must run for both -
        // otherwise a PUT reaches the save with an empty $params and skips the SG guard.
        if ($this->request->is('post') || $this->request->is('put')) {
            $data = $this->request->data;
            $params = [
                'redirect' => $attachTarget === null
                    ? ['action' => 'index']
                    : $this->referer(['controller' => 'collections', 'action' => 'index'], true),
                'beforeSave' => function (array $collection) use ($currentUser, $attachTarget) {
                    if (isset($collection['Collection']['distribution']) && $collection['Collection']['distribution'] == 4) {
                        $canSGBeUsed = $this->Event->SharingGroup->checkIfCanBeUsed($currentUser, $this->_isRest(), $collection, 'Collection');
                        if ($canSGBeUsed !== true) {
                            throw new MethodNotAllowedException($canSGBeUsed);
                        }
                    }
                    if ($attachTarget !== null) {
                        $this->Collection->CollectionElement->assertTargetsUsable($currentUser, $attachTarget['type'], $attachTarget['uuids']);
                    }
                    $this->__assertCanUseNestedElements($collection);
                    return $collection;
                },
                'afterSave' => function (array $collection) use ($attachTarget) {
                    $this->Collection->CollectionElement->captureElements($collection);
                    if ($attachTarget !== null) {
                        foreach ($attachTarget['uuids'] as $attachElementUuid) {
                            $this->__attachElementToCollection(
                                $collection['Collection']['id'],
                                $attachTarget['type'],
                                $attachElementUuid,
                                $attachTarget['description'] ?? ''
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
            'types' => array_combine(Collection::VALID_TYPES, Collection::VALID_TYPES),
            'distributionLevels' => $this->Event->distributionLevels,
            'sgs' => $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1)  
        ];
        $this->set('initialDistribution', Configure::read('MISP.default_event_distribution'));
        // Rendered inside the collection picker's modal rather than as a modal of
        // its own: the view then drops the header strip and the attach banner the
        // picker is already showing.
        // GET only: a rejected save re-renders this view as a whole page, which
        // needs its header back.
        $this->set('embedded', $this->request->is('get') && (bool)$this->request->query('embedded'));
        $attachElementDescription = $attachTarget['description'] ?? '';
        $this->set(compact('dropdownData', 'attachElementType', 'attachElementUuid', 'attachElementUuids', 'attachElementLabels', 'attachElementDescription'));
        if($this->theme === "Overmind"){
            $this->layout = false;
        }
        $this->render('add');
    }

    private function __getAttachTargetFromRequest()
    {
        $attachElementType = null;
        $attachElementUuids = [];
        $attachElementDescription = '';

        if ($this->request->is('post')) {
            if (!empty($this->request->data['Collection']['_attach_element_type'])) {
                $attachElementType = $this->request->data['Collection']['_attach_element_type'];
            }
            if (!empty($this->request->data['Collection']['_attach_element_uuid'])) {
                $attachElementUuids = (array)$this->request->data['Collection']['_attach_element_uuid'];
            }
            if (isset($this->request->data['Collection']['_attach_element_description'])) {
                $description = $this->request->data['Collection']['_attach_element_description'];
                $attachElementDescription = is_scalar($description) ? trim((string)$description) : '';
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
        $column = AnalystData::addressColumn($attachElementType, 'element');
        foreach ($attachElementUuids as $i => $attachElementUuid) {
            if ($column === 'element_sha256') {
                $attachElementUuids[$i] = $attachElementUuid = strtolower($attachElementUuid);
            }
            $row = ['element_type' => $attachElementType, $column => $attachElementUuid];
            if (AnalystData::addressError($row, $column) !== null) {
                throw new BadRequestException(__('Invalid element address for collection attachment.'));
            }
        }
        $attachElementUuids = array_values(array_unique($attachElementUuids));

        return [
            'type' => $attachElementType,
            'uuid' => $attachElementUuids[0],
            'uuids' => $attachElementUuids,
            'description' => $attachElementDescription,
        ];
    }

    /**
     * The caller has already checked the target, see add()'s beforeSave.
     */
    private function __attachElementToCollection($collectionId, $elementType, $elementUuid, $description = '')
    {
        $this->Collection->CollectionElement->create();
        try {
            $this->Collection->CollectionElement->save([
                'CollectionElement' => [
                    'collection_id' => $collectionId,
                    'element_type' => $elementType,
                    AnalystData::addressColumn($elementType, 'element') => $elementUuid,
                    'description' => $description
                ]
            ]);
        } catch (PDOException $e) {
            // Collection create can be retried safely; ignore duplicate attachment rows.
            if (!CollectionElement::isDuplicate($e)) {
                throw $e;
            }
        }
    }

    /**
     * Elements nested in a REST body are saved by captureElements(), which
     * sync uses too and so checks nothing: check them here. One already in the
     * collection is not checked again, so a target that has since gone away
     * does not block the edit.
     *
     * @param array $collection the record about to be saved
     * @param int|null $collectionId null on create
     * @throws NotFoundException
     */
    private function __assertCanUseNestedElements(array $collection, $collectionId = null)
    {
        $elements = $collection['Collection']['CollectionElement'] ?? null;
        if (!is_array($elements)) {
            return;
        }
        $known = [];
        if ($collectionId !== null) {
            $stored = $this->Collection->CollectionElement->find('all', [
                'recursive' => -1,
                'conditions' => ['CollectionElement.collection_id' => $collectionId],
                'fields' => ['element_type', 'element_uuid', 'element_sha256'],
            ]);
            foreach ($stored as $element) {
                $type = $element['CollectionElement']['element_type'];
                $address = $element['CollectionElement'][AnalystData::addressColumn($type, 'element')];
                $known[$type . ':' . strtolower((string)$address)] = true;
            }
        }
        foreach ($elements as $element) {
            if (!is_array($element)) {
                continue;
            }
            $type = $element['element_type'] ?? null;
            $address = $element[AnalystData::addressColumn($type, 'element')] ?? null;
            if (!is_scalar($address) || trim((string)$address) === '') {
                continue;
            }
            $address = trim((string)$address);
            if (isset($known[$type . ':' . strtolower($address)])) {
                continue;
            }
            $this->Collection->CollectionElement->assertTargetsUsable($this->Auth->user(), $type, [$address]);
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
                    // locked is a sync-integrity flag set only by captureCollection (as a
                    // perm_sync user); the web edit path must never change it, otherwise an
                    // owner could flip locked and bypass the create-time guard in
                    // Collection::beforeValidate. Pin it to the stored value.
                    'locked' => $oldCollection['Collection']['locked'],
                    // CRUD edit keeps the stored value, and sync only sees a newer `modified`.
                    'modified' => date('Y-m-d H:i:s'),
                ],
                'beforeSave' => function (array $collection) use ($id) {
                    $this->__assertCanUseNestedElements($collection, (int)$id);
                    return $collection;
                },
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
            'types' => array_combine(Collection::VALID_TYPES, Collection::VALID_TYPES),
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
        if ($this->IndexFilter->isRest()) {
            $this->Collection->includeAnalystData = true;
            $this->Collection->includeAnalystDataRecursive = true;
        }
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
        if (!$this->IndexFilter->isRest()) {
            $params['contain'][] = 'SharingGroup';
        }
        $this->CRUD->view($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $data = $this->viewVars['data'];
        $sharingGroupId = $data['Collection']['SharingGroup']['id'] ?? null;
        if (!empty($sharingGroupId)) {
            $data['Collection']['SharingGroup']['org_count'] = $this->Collection->SharingGroup->SharingGroupOrg->find('count', [
                'conditions' => ['SharingGroupOrg.sharing_group_id' => $sharingGroupId],
            ]);
            $this->set('data', $data);
        }
        $elements = $data['Collection']['CollectionElement'] ?? [];

        $elements = $this->Collection->CollectionElement->attachTargets($user, $elements);
        $data['Collection']['CollectionElement'] = $elements;
        $this->set('data', $data);

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

        if ($this->theme === 'Overmind') {
            $railCards = new CollectionRailCards();
            $this->set('railCards', RailCard::byId([
                $railCards->inventory($elements),
                $railCards->sources($elements),
            ]));
        }

        $this->set('id', $id);
        $this->set('publishState', $this->__publishState($user, $id));
        $this->loadModel('Event');
        $this->set('distributionLevels', $this->Event->distributionLevels);
        $this->render('view');
    }

    public function index($filter = null)
    {
        $this->set('menuData', array('menuList' => 'collections', 'menuItem' => 'index'));
        $params = [
            'filters' => ['Collection.uuid', 'Collection.type', 'type', 'Collection.name'],
            'quickFilters' => ['Collection.name'],
            'contain' => ['Orgc', 'SharingGroup'],
            'afterFind' => function($collections) {
                $user = $this->Auth->user();
                foreach ($collections as $k => $collection) {
                    $collections[$k]['Collection']['element_count'] = $this->Collection->CollectionElement->find('count', [
                        'recursive' => -1,
                        'conditions' => ['CollectionElement.collection_id' => $collection['Collection']['id']]
                    ]);
                    if (!empty($collection['CollectionElement']) && !Collection::showsAdders($user, $collection['Collection'])) {
                        $collections[$k]['CollectionElement'] = Collection::withoutAdders($collection['CollectionElement']);
                    }
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
        if ($this->_isRest()) {
            // The sync pull fetches full collections by uuid through this action
            // (ServerSyncTool::fetchCollections -> GET /collections/index/uuid[]:...json).
            // The capture sink needs the element corpus — even when empty — to perform an
            // authoritative replace (D5), so include CollectionElement for REST callers
            // only. The HTML index shows just element_count and must not eager-load every
            // element across the paginated list.
            if (SyncTool::valueTargetsWithheld()) {
                $params['contain']['CollectionElement'] = ['conditions' => ['CollectionElement.element_sha256' => null]];
            } else {
                $params['contain'][] = 'CollectionElement';
            }
            // The generic index filter list registers the fully-qualified 'Collection.uuid'
            // key, but harvestParameters only matches a named param whose key is literally
            // 'Collection.uuid'. The sync client sends bare uuid[] named params, so harvest
            // them here into an explicit, alias-qualified IN() condition. A bare 'uuid'
            // filter would be ambiguous against the joined Orgc/SharingGroup uuid columns.
            $uuidFilter = $this->request->params['named']['uuid'] ?? null;
            if (!empty($uuidFilter)) {
                $params['conditions']['AND'][] = ['Collection.uuid' => (array)$uuidFilter];
            }
            if (SyncTool::requesterIsMisp()) {
                $params['conditions']['AND'][] = Collection::releasedConditions();
            }
        }
        $this->loadModel('Event');
        $this->set('distributionLevels', $this->Event->distributionLevels);
        $this->set('dropdownData', [
            'types' => array_combine(Collection::VALID_TYPES, Collection::VALID_TYPES)
        ]);
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    /**
     * Minimal index endpoint used by a remote instance during a sync pull: returns
     * { uuid: modified } for every collection the caller may see + distribute (filtered
     * inside Collection::indexMinimal via buildConditions), optionally narrowed by
     * orgc_name OR/NOT pull-rules. Mirrors AnalystDataController::indexMinimal. CSRF is
     * auto-unlocked for REST (AppController::beforeFilter); the ACL entry is ['*'] and
     * visibility is enforced by buildConditions rather than a blanket perm_sync gate.
     */
    public function indexMinimal()
    {
        $filters = [];
        if ($this->request->is('post')) {
            $filters = $this->request->data;
        }
        $options = [];
        if (!empty($filters['orgc_name'])) {
            // Resolve names through a canonically-aliased Organisation model: fetchOrg()
            // hardcodes a `LOWER(Organisation.name)` condition, so calling it via the
            // Collection->Orgc association (alias 'Orgc') would emit an unknown-column error.
            $this->loadModel('Organisation');
            $orgcNames = $filters['orgc_name'];
            if (!is_array($orgcNames)) {
                $orgcNames = [$orgcNames];
            }
            // Track whether an OR-rule (allow-list) was supplied separately from
            // whether it resolved: a NOT-rule against an org that doesn't exist
            // locally should impose no restriction, not exclude everything. Only
            // "caller asked for specific orgs, none exist" should return nothing.
            $hasOrRule = false;
            foreach ($orgcNames as $orgcName) {
                if (!is_string($orgcName) || $orgcName === '') {
                    continue;
                }
                // Collections key the creator org by integer FK (orgc_id), not the
                // orgc_uuid string column that analyst data filters on — resolve the
                // name to a local org id before building the condition.
                if ($orgcName[0] === '!') {
                    $orgc = $this->Organisation->fetchOrg(substr($orgcName, 1));
                    if ($orgc === false) {
                        continue;
                    }
                    $options[]['AND'][] = ['Collection.orgc_id !=' => $orgc['id']];
                } else {
                    $hasOrRule = true;
                    $orgc = $this->Organisation->fetchOrg($orgcName);
                    if ($orgc === false) {
                        continue;
                    }
                    $options['OR'][] = ['Collection.orgc_id' => $orgc['id']];
                }
            }
            if ($hasOrRule && empty($options['OR'])) {
                return $this->RestResponse->viewData([], $this->response->type());
            }
        }
        $allData = $this->Collection->indexMinimal($this->Auth->user(), $options);
        return $this->RestResponse->viewData($allData, $this->response->type());
    }

    /**
     * Push-receive dedup handshake. The pushing peer sends its {uuid: modified} candidates;
     * we reply with the subset this instance actually wants (missing locally, or strictly
     * newer than a synced-in local copy). Mirrors AnalystDataController::filterAnalystDataForPush.
     * REST/CSRF auto-unlocked; ACL gated on perm_sync.
     *
     * POST /collections/filterCollectionsForPush
     */
    public function filterCollectionsForPush()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('This function is only accessible via POST requests.'));
        }
        $allIncomingCollections = $this->request->data;
        $wantedUuids = $this->Collection->filterCollectionsForPush($allIncomingCollections);
        return $this->RestResponse->viewData($wantedUuids, $this->response->type());
    }

    /**
     * Push-receive upload endpoint. The pushing peer uploads one collection (nested under
     * Collection, with its Orgc / SharingGroup / CollectionElement corpus); we hand the RAW
     * payload to the shared Collection::captureCollection sink, which owns the distribution
     * downgrade, locked=1 and the D6 conflict rule. Push-receive passes $server=false and
     * remotePermSyncInternal from the pushing user's own role (contrast pull, which passes
     * the server + the remote cachedUserInfo). Mirrors AnalystDataController::pushAnalystData.
     * REST/CSRF auto-unlocked; in-action perm_sync + _isRest() gate on top of the ACL entry.
     *
     * POST /collections/captureCollection
     */
    public function captureCollection()
    {
        if (!$this->Auth->user()['Role']['perm_sync']) {
            throw new MethodNotAllowedException(__('You do not have the permission to do that.'));
        }
        if (!$this->_isRest()) {
            throw new MethodNotAllowedException(__('This action is only accessible via a REST request.'));
        }
        if ($this->request->is('post')) {
            $collection = $this->request->data;
            $saveResult = $this->Collection->captureCollection(
                $this->Auth->user(),
                $collection,
                false,
                !empty($this->Auth->user()['Role']['perm_sync_internal'])
            );
            $messageInfo = __('%s imported, %s ignored, %s failed. %s', $saveResult['imported'], $saveResult['ignored'], $saveResult['failed'], !empty($saveResult['errors']) ? implode(', ', $saveResult['errors']) : '');
            if ($saveResult['success']) {
                $message = __('Collection imported. ') . $messageInfo;
                return $this->RestResponse->saveSuccessResponse('Collection', 'captureCollection', false, $this->response->type(), $message);
            } else {
                $message = __('Could not import collection. ') . $messageInfo;
                return $this->RestResponse->saveFailResponse('Collection', 'captureCollection', false, $message);
            }
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
        return $this->RestResponse->viewData(current($result) ?: [], $this->response->type());
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

    /**
     * Only the collections' own ACL applies, not the elements' targets.
     *
     * @param string $elementType
     * @param array $uuids uuids, or SHA-256s for AnalystData::SHA256_TARGETS
     * @return array address => collections; a SHA-256 in lower case
     */
    private function __getCollectionsByElementUuids($elementType, array $uuids)
    {
        $column = AnalystData::addressColumn($elementType, 'element');
        if ($column === 'element_sha256') {
            $uuids = array_map(function ($hex) {
                return is_string($hex) ? strtolower($hex) : $hex;
            }, $uuids);
        }
        $uuids = array_values(array_unique(array_filter($uuids, 'is_string')));
        if (empty($uuids)) {
            return [];
        }

        $this->loadModel('CollectionElement');
        $elements = $this->CollectionElement->find('all', [
            'recursive' => -1,
            'conditions' => [
                'CollectionElement.element_type' => $elementType,
                'CollectionElement.' . $column => $uuids
            ],
            'fields' => ['CollectionElement.collection_id', 'CollectionElement.' . $column]
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
            $elementUuid = $element['CollectionElement'][$column];
            if (!isset($collectionsById[$collectionId])) {
                continue;
            }
            $result[$elementUuid][] = $collectionsById[$collectionId];
        }

        return $result;
    }
}
