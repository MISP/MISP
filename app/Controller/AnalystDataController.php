<?php
App::uses('AppController', 'Controller');
App::uses('AnalystDataRailCards', 'Tools/RailCards');
App::uses('AnalystData', 'Model');

class AnalystDataController extends AppController
{

    public $components = ['Session', 'RequestHandler'];

    public $paginate = [
        'limit' => 60,
        'order' => []
    ];

    public $uses = [
        'Opinion',
        'Note',
        'Relationship',
        'Graph'
    ];

    private $__valid_types = [
        'Opinion',
        'Note',
        'Relationship',
        'Graph'
    ];

    // public $modelSelection = 'Note';

    public function beforeFilter()
    {
        parent::beforeFilter();
        // The event pivot explorer posts hand-built JSON to add() and delete(),
        // and the graph page's settings to edit(), so they send the CSRF token
        // as the X-CSRF-Token header.
        $this->_csrfTokenHeaderOnly(['add', 'edit', 'delete']);
    }

    private function _setViewElements()
    {
        $dropdownData = [];
        $this->loadModel('Event');
        $dropdownData['distributionLevels'] = $this->Event->distributionLevels;
        $this->set('initialDistribution', Configure::read('MISP.default_event_distribution'));
        $dropdownData['sgs'] = $this->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', 1);
        $dropdownData['valid_targets'] = array_combine($this->AnalystData::valid_targets, $this->AnalystData::valid_targets);
        $this->set(compact('dropdownData'));
        $this->set('modelSelection', $this->modelSelection);
        $this->set('distributionLevels', $this->Event->distributionLevels);
        App::uses('LanguageRFC5646Tool', 'Tools');
        $this->set('languageRFC5646', ['' => __('- No language -'), LanguageRFC5646Tool::getLanguages()]);
    }

    public function add($type = 'Note', $object_address = null, $object_type = null)
    {
        $this->__typeSelector($type);
        $model = $this->modelSelection;
        if (!empty($object_type)) {
            $this->request->data[$model]['object_type'] = $object_type;
        }
        if (empty($this->request->data[$model]['object_type'])) {
            // A SHA-256 only ever addresses a value; deduceType() knows uuids only
            $hash = $object_address ?? $this->request->data[$model]['object_sha256'] ?? null;
            if (is_string($hash) && preg_match('/^[0-9a-f]{64}$/i', trim($hash))) {
                $this->request->data[$model]['object_type'] = 'AttributeValue';
            }
        }
        if (!empty($object_address)) {
            $column = AnalystData::addressColumn($this->request->data[$model]['object_type'] ?? null, 'object');
            $this->request->data[$model][$column] = $object_address;
        }

        if (empty($this->request->data[$model]['object_type']) && !empty($this->request->data[$model]['object_uuid'])) {
            throw new BadRequestException(__('object_type is required.'));
        }
        $this->loadModel('Event');
        $currentUser = $this->Auth->user();
        $params = [
            // Return to where the modal was opened (event view, hub index, ...)
            'redirect' => $this->referer(['action' => 'index', $this->modelSelection], true),
            'beforeSave' => function(array $analystData) use ($currentUser) {
                if (isset($analystData[$this->modelSelection]['distribution']) && $analystData[$this->modelSelection]['distribution'] == 4) {
                    $canSGBeUsed = $this->Event->SharingGroup->checkIfCanBeUsed($currentUser, $this->_isRest(), $analystData, $this->modelSelection);
                    if ($canSGBeUsed !== true) {
                        throw new MethodNotAllowedException($canSGBeUsed);
                    }
                }
                if ($this->modelSelection === 'Graph') {
                    // Only a fork records what it was forked from
                    unset($analystData['Graph']['forked_from_uuid']);
                    if (isset($analystData['Graph']['content'])) {
                        $analystData['Graph']['content'] = $this->AnalystData->contentForWrite($currentUser, $analystData['Graph']['content']);
                    }
                }
                return $analystData;
            },
            'afterSave' => function (array $analystData) use ($currentUser) {
                $this->Event->captureAnalystData($currentUser, $this->request->data[$this->modelSelection], $this->modelSelection, $analystData[$this->modelSelection]['uuid']);
            },
            'afterFind' => function (array $analystData) {
                return $this->__decodeGraphContent($analystData);
            },
        ];
        $this->CRUD->add($params);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }

        if (($this->theme ?? null) === 'Overmind' && $this->request->is('post')) {
            return $this->redirect(['action' => 'index', $this->modelSelection]);
        }
        $this->_setViewElements();
        if ($type == 'Relationship') {
            $this->set('existingRelations', $this->AnalystData->getExistingRelationships());
        }

        if (($this->theme ?? null) === 'Overmind' && $this->request->is('ajax')) {
            $this->layout = false;
        }
        $this->set('menuData', array('menuList' => 'analyst_data', 'menuItem' => 'add_' . strtolower($type)));
        $this->render('add');
    }

    public function edit($type = 'Note', $id)
    {
        if ($type === 'all' && Validation::uuid($id)) {
            $this->loadModel('AnalystData');
            $type = $this->AnalystData->deduceType($this->Auth->user(), $id);
        }
        $this->__typeSelector($type);
        if (!is_numeric($id) && Validation::uuid($id)) {
            $id = $this->AnalystData->getIDFromUUID($type, $id);
        }

        $this->set('id', $id);
        $conditions = $this->AnalystData->buildConditions($this->Auth->user());
        $this->loadModel('Event');
        $currentUser = $this->Auth->user();
        $params = [
            'redirect' => $this->referer(['action' => 'index', $this->modelSelection], true),
            'fields' => $this->AnalystData->getEditableFields(),
            'conditions' => $conditions,
            'afterFind' => function(array $analystData): array {
                $canEdit = $this->ACL->canEditAnalystData($this->Auth->user(), $analystData, $this->modelSelection);
                if (!$canEdit) {
                    throw new MethodNotAllowedException(__('You are not authorised to do that.'));
                }
                return $analystData;
            },
            'beforeSave' => function (array $analystData) use ($currentUser): array {
                if (isset($analystData[$this->modelSelection]['distribution']) && $analystData[$this->modelSelection]['distribution'] == 4) {
                    $canSGBeUsed = $this->Event->SharingGroup->checkIfCanBeUsed($currentUser, $this->_isRest(), $analystData, $this->modelSelection);
                    if ($canSGBeUsed !== true) {
                        throw new MethodNotAllowedException($canSGBeUsed);
                    }
                }
                $analystData[$this->modelSelection]['modified'] = date('Y-m-d H:i:s');
                if ($this->modelSelection === 'Graph') {
                    // The document is written by a revision-checked save only:
                    // writing back the copy loaded here would undo one made since
                    unset($analystData['Graph']['content'], $analystData['Graph']['content_size'], $analystData['Graph']['node_count']);
                }
                return $analystData;
            },
            'afterSave' => function (array $analystData) use ($currentUser) {
                $this->Event->captureAnalystData($currentUser, $this->request->data[$this->modelSelection], $this->modelSelection, $analystData[$this->modelSelection]['uuid']);
            }
        ];
        $this->CRUD->edit($id, $params);
        if ($this->IndexFilter->isRest()) {
            // A GET answers with the record it would edit
            return $this->restResponsePayload
                ?? $this->RestResponse->viewData($this->__decodeGraphContent($this->viewVars['entity']), 'json');
        }

        if (($this->theme ?? null) === 'Overmind' && $this->request->is('post')) {
            return $this->redirect(['action' => 'index', $this->modelSelection]);
        }
        $this->_setViewElements();
        if ($type == 'Relationship') {
            $this->set('existingRelations', $this->AnalystData->getExistingRelationships());
        }

        if (($this->theme ?? null) === 'Overmind' && $this->request->is('ajax')) {
            $this->layout = false;
        }
        $this->set('menuData', array('menuList' => 'analyst_data', 'menuItem' => 'edit'));
        $this->render('add');
    }

    public function delete($type = 'Note', $id, $hard=true)
    {
        if ($type === 'all' && Validation::uuid($id)) {
            $this->loadModel('AnalystData');
            $type = $this->AnalystData->deduceType($this->Auth->user(), $id);
        }
        $this->__typeSelector($type);
        if (!is_numeric($id) && Validation::uuid($id)) {
            $id = $this->AnalystData->getIDFromUUID($type, $id);
        }

        if (($this->theme ?? null) === 'Overmind' && $this->request->is('ajax')
            && !($this->request->is('post') || $this->request->is('delete'))) {
            $this->layout = false;
            $this->set('adType', $this->modelSelection);
            $this->set('adId', $id);
            return $this->render('ajax/delete_confirmation');
        }

        $params = [
            'redirect' => ['action' => 'index', $this->modelSelection],
            'afterFind' => function(array $analystData) {
                $canEdit = $this->ACL->canEditAnalystData($this->Auth->user(), $analystData, $this->modelSelection);
                if (!$canEdit) {
                    throw new MethodNotAllowedException(__('You are not authorised to do that.'));
                }
                return $analystData;
            },
            'afterDelete' => function($deletedAnalystData) use ($hard) {
                if (!empty($hard)) {
                    $this->__blocklistDeletedAnalystData($deletedAnalystData);
                }
            }
        ];
        $this->CRUD->delete($id, $params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    public function deleteSelection($type = 'Note', $ids = null, $hard = true)
    {
        $this->__typeSelector($type);
        $model = $this->modelSelection;

        if ($this->request->is(['post', 'put', 'delete'])) {
            $idList = $this->request->data[$model]['id'] ?? $ids;
            if (!is_array($idList)) {
                $idList = json_decode($idList, true);
            }
            if (empty($idList)) {
                throw new NotFoundException(__('Invalid input.'));
            }
            $user = $this->Auth->user();
            $successes = 0;
            $fails = 0;
            foreach ($idList as $cid) {
                $item = $this->{$model}->find('first', [
                    'recursive' => -1,
                    'conditions' => Validation::uuid($cid)
                        ? [$model . '.uuid' => $cid]
                        : [$model . '.id' => $cid],
                ]);
                if (empty($item) || !$this->ACL->canEditAnalystData($user, $item, $model)) {
                    $fails++;
                    continue;
                }
                if ($this->{$model}->delete($item[$model]['id'])) {
                    $successes++;
                    if (!empty($hard)) {
                        $this->__blocklistDeletedAnalystData($item);
                    }
                } else {
                    $fails++;
                }
            }
            $message = __n('%s %s deleted.', '%s %ss deleted.', $successes, $successes, strtolower($model));
            if ($fails) {
                $message .= ' ' . __('%s could not be deleted (insufficient privileges or not found).', $fails);
            }
            if ($this->IndexFilter->isRest()) {
                return $this->RestResponse->saveSuccessResponse($model, 'deleteSelection', false, $this->response->type(), $message);
            }
            if ($successes) {
                $this->Flash->success($message);
            } else {
                $this->Flash->error($message);
            }
            return $this->redirect(['action' => 'index', $model]);
        }

        // GET → confirmation modal listing the selection.
        $idList = json_decode($ids, true);
        if (empty($idList)) {
            throw new NotFoundException(__('Invalid input.'));
        }
        $this->request->data[$model]['id'] = json_encode($idList);
        $this->set('idArray', $idList);
        $this->set('adType', $model);
        $this->layout = false;
        $this->render('ajax/delete_selection_confirmation');
    }

    /**
     * Add a deleted analyst-data item to the blocklist so it is not re-imported on
     * the next sync. Shared by delete() and deleteSelection().
     */
    private function __blocklistDeletedAnalystData(array $deletedAnalystData)
    {
        $type = $this->AnalystData->deduceAnalystDataType($deletedAnalystData);
        $info = '- Unsupported analyst type -';
        if ($type === 'Note') {
            $info = $deletedAnalystData[$type]['note'];
        } else if ($type === 'Opinion') {
            $info = sprintf('%s/100 :: %s', $deletedAnalystData[$type]['opinion'], $deletedAnalystData[$type]['comment']);
        } else if ($type === 'Relationship') {
            $info = sprintf('-- %s --> %s :: %s', $deletedAnalystData[$type]['relationship_type'] ?? '[undefined]', $deletedAnalystData[$type]['related_object_type'], $deletedAnalystData[$type]['related_object_uuid']);
        } else if ($type === 'Graph') {
            $info = $deletedAnalystData[$type]['name'];
        }
        $blocklist = ClassRegistry::init('AnalystDataBlocklist');
        $blocklist->create();
        if (!empty($deletedAnalystData[$type]['orgc_uuid'])) {
            if (!empty($deletedAnalystData[$type]['Orgc'])) {
                $orgc = $deletedAnalystData[$type];
            } else {
                $orgc = ClassRegistry::init('Orgc')->find('first', array(
                    'conditions' => ['Orgc.uuid' => $deletedAnalystData[$type]['orgc_uuid']],
                    'recursive' => -1,
                    'fields' => ['Orgc.name'],
                ));
            }
        } else {
            $orgc = ['Orgc' => ['name' => 'MISP']];
        }
        $blocklist->save(['analyst_data_uuid' => $deletedAnalystData[$type]['uuid'], 'analyst_data_info' => $info, 'analyst_data_orgc' => $orgc['Orgc']['name']]);
    }

    public function view($type = 'Note', $id)
    {
        if ($type === 'all' && Validation::uuid($id)) {
            $this->loadModel('AnalystData');
            $type = $this->AnalystData->deduceType($this->Auth->user(), $id);
        }
        $this->__typeSelector($type);
        if (!is_numeric($id) && Validation::uuid($id)) {
            $id = $this->AnalystData->getIDFromUUID($type, $id);
        }

        if ($this->modelSelection === 'Graph' && !$this->_isRest() && !$this->request->is('ajax')) {
            $graph = $this->AnalystData->find('first', [
                'conditions' => ['AND' => [[$this->AnalystData->alias . '.id' => $id], $this->AnalystData->buildConditions($this->Auth->user())]],
                'fields' => [$this->AnalystData->alias . '.uuid'],
                'recursive' => -1,
                'callbacks' => false,
            ]);
            if (empty($graph)) {
                throw new NotFoundException(__('Invalid graph.'));
            }
            return $this->redirect('/analyst_graphs/view/' . $graph[$this->AnalystData->alias]['uuid']);
        }

        $this->AnalystData->fetchRecursive = false;
        $conditions = $this->AnalystData->buildConditions($this->Auth->user());
        $this->CRUD->view($id, [
            'conditions' => $conditions,
            'contain' => ['Org', 'Orgc'],
            'afterFind' => function(array $analystData) {
                if (!$this->request->is('ajax')) {
                    unset($analystData[$this->modelSelection]['_canEdit']);
                }
                if ($this->_isRest()) {
                    $analystData = $this->__decodeGraphContent($analystData);
                    $children = $this->AnalystData->fetchChildNotesAndOpinions($this->Auth->user(), $analystData[$this->modelSelection], true, 5);
                    if (!empty($children)) {
                        foreach ($children as $child) {
                            foreach ($child as $childType => $childData) {
                                $analystData[$this->modelSelection][$childType][] = $childData;
                            }
                        }
                    }
                } else {
                    $children = $this->AnalystData->fetchChildNotesAndOpinions($this->Auth->user(), $analystData[$this->modelSelection], false, 1);
                    $analystData[$this->modelSelection] = $analystData[$this->modelSelection] + $children;
                }
                return $analystData;
            }
        ]);

        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        if ($this->theme === 'Overmind') {
            $user = $this->Auth->user();
            $record = $this->viewVars['data'][$this->modelSelection];
            $railCards = new AnalystDataRailCards();
            $this->set('railCards', RailCard::byId([
                $railCards->target($user, $record),
                $railCards->thread($record),
            ]));
            $this->set('mayModify', $this->ACL->canUserAccess($user, 'analystData', 'edit')
                && $this->AnalystData->canEditAnalystData($user, $this->viewVars['data'], $this->modelSelection));
        }
        $this->set('id', $id);
        $record = $this->viewVars['data'][$this->modelSelection] ?? [];
        $targets = [];
        foreach (['object', 'related_object'] as $end) {
            $type = $record[$end . '_type'] ?? '';
            $address = $record[AnalystData::addressColumn($type, $end)] ?? '';
            if (!empty($address)) {
                $targets[] = ['type' => $type, 'address' => $address];
            }
        }
        $this->set('analystTargets', $this->AnalystData->describeTargets($this->Auth->user(), $targets));
        $this->loadModel('Event');
        $this->_setViewElements();
        $this->set('distributionLevels', $this->Event->distributionLevels);
        $this->set('shortDist', $this->Event->shortDist);
        $this->set('menuData', array('menuList' => 'analyst_data', 'menuItem' => 'view'));
        $this->render('view');
    }

    public function index($type = null)
    {
        $overmind = ($this->theme ?? null) === 'Overmind';
        $isAjax = $this->request->is('ajax');
        if ($overmind && !$isAjax && !$this->_isRest()) {
            $selectedType = in_array($type, $this->__valid_types, true) ? $type : null;
            return $this->__hub($selectedType);
        }
        if (empty($type)) {
            $type = 'Note'; // preserve the historical default (REST + non-Overmind themes)
        }
        $this->__typeSelector($type);
        if (isset($this->request->data[$type])) {
            $this->request->data = $this->request->data[$type];
        }
        // PostgreSQL compares the SHA-256 columns case-sensitively
        $lower = function ($hex) {
            return is_string($hex) ? strtolower($hex) : $hex;
        };
        if (isset($this->request->data['object_sha256'])) {
            $hexes = $this->request->data['object_sha256'];
            $this->request->data['object_sha256'] = is_array($hexes) ? array_map($lower, $hexes) : $lower($hexes);
        }
        if (isset($this->request->params['named']['object_sha256'])) {
            $this->request->params['named']['object_sha256'] = $lower($this->request->params['named']['object_sha256']);
        }
        $conditions = $this->AnalystData->buildConditions($this->Auth->user());
        $params = [
            'filters' => array_merge(['uuid', 'target_object', 'object_sha256'], $this->AnalystData::SEARCHABLE_FIELDS),
            'quickFilters' => $this->AnalystData::SEARCHABLE_FIELDS,
            'conditions' => $conditions,
            'afterFind' => function(array $data) {
                foreach ($data as $i => $analystData) {
                    if (!$this->request->is('ajax')) {
                        unset($analystData[$this->modelSelection]['_canEdit']);
                    }
                    if ($this->_isRest()) {
                        $data[$i] = $analystData;
                    }
                }
                if ($this->_isRest()) {
                    $data = $this->__decodeGraphContents($data);
                }
                if ($this->modelSelection === 'Graph' && !$this->_isRest()) {
                    $data = $this->__countGraphNodes($data);
                }
                return $data;
            }
        ];
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }

        if ($overmind && $isAjax) {
            $this->layout = false;
        }
        if ($overmind) {
            $this->__setTargetExistence($this->viewVars['data'] ?? []);
        }
        $this->_setViewElements();
        $this->set('menuData', array('menuList' => 'analyst_data', 'menuItem' => 'index'));
    }

    /**
     * Each graph's node count as the user sees it, in place of the stored one
     * (G6), its original when it is a fork, and no document.
     *
     * @param array $data Graph rows
     * @return array
     */
    private function __countGraphNodes(array $data)
    {
        $contents = $graphs = [];
        foreach ($data as $i => $row) {
            $contents[$i] = $row['Graph']['content'] ?? null;
            $graphs[$i] = $row['Graph'];
        }
        $user = $this->Auth->user();
        $counts = ClassRegistry::init('AnalystGraphData')->visibleCounts($user, $contents);
        $parents = $this->AnalystData->withParents($user, $graphs);
        foreach ($data as $i => $row) {
            $data[$i]['Graph']['node_count'] = $counts[$i];
            $data[$i]['Graph']['forked_from'] = $parents[$i]['forked_from'];
            unset($data[$i]['Graph']['content'], $data[$i]['Graph']['content_size']);
        }
        return $data;
    }

    /**
     * Tell the index which of the rendered targets still resolve, so a UUID
     * pointing at something this instance no longer holds is rendered as text
     * instead of a link into a "not found" page.
     *
     * @param array $rows the page of analyst data about to be rendered
     */
    private function __setTargetExistence(array $rows)
    {
        $model = $this->modelSelection;
        $targets = [];
        foreach ($rows as $row) {
            foreach (['object', 'related_object'] as $end) {
                $type = $row[$model][$end . '_type'] ?? '';
                $address = $row[$model][AnalystData::addressColumn($type, $end)] ?? '';
                if (!empty($address)) {
                    $targets[] = [
                        'type' => $type,
                        'address' => $address,
                    ];
                }
            }
        }
        $this->set(
            'analystTargetExists',
            $this->AnalystData->existingTargets($this->Auth->user(), $targets)
        );
    }

    /**
     * Let the user pick which analyst data index to open,
     * Counts run with callbacks disabled to skip AnalystData::afterFind .
     * When $selectedType is set, the hub also loads that type's index below the cards.
     */
    private function __hub($selectedType = null)
    {
        $user = $this->Auth->user();
        $counts = [];
        foreach ($this->__valid_types as $vt) {
            $this->loadModel($vt);
            $this->{$vt}->current_user = $user;
            $conditions = $this->{$vt}->buildConditions($user);
            $counts[$vt] = $this->{$vt}->find('count', [
                'conditions' => $conditions,
                'callbacks' => false,
            ]);
        }
        $this->set('counts', $counts);
        $this->set('selectedType', $selectedType);
        $this->set('menuData', array('menuList' => 'analyst_data', 'menuItem' => 'index'));
        $this->render('hub');
    }

    /**
     * Read-only summary of the analyst data attached to a given object.
     * Rendered as a body-only modal fragment for the Overmind theme,
     * opened via openModal from the analyst-data count badges in the index tables.
     */
    public function viewForObject($object_type, $object_address)
    {
        // The type never selects a model here, it is only matched and rendered,
        // so anything outside the parent types analyst data can hang off is a
        // malformed request rather than a lookup that finds nothing.
        if (!in_array($object_type, AnalystData::valid_targets, true)) {
            throw new NotFoundException(__('Invalid object type.'));
        }
        // Only the analyst data's own ACL applies, not the target's: a value
        // the user cannot see is deliberately not checked for, as with uuids
        if (in_array($object_type, AnalystData::SHA256_TARGETS, true)) {
            $object_address = strtolower(trim($object_address));
        }
        $this->loadModel('Note');
        $analystData = $this->Note->fetchThreadForObject($this->Auth->user(), $object_type, $object_address);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($analystData, 'json');
        }
        $this->set('analystData', $analystData);
        $this->set('objectType', $object_type);
        $this->set('objectUuid', $object_address);
        $this->layout = false;
        $this->render('ajax/object_thread');
    }

    public function getRelatedElement($type, $uuid)
    {
        $this->__typeSelector('Relationship');
        $data = $this->AnalystData->getRelatedElement($this->Auth->user(), $type, $uuid);
        return $this->RestResponse->viewData($data, 'json');
    }

    public function getChildren($type = 'Note', $uuid, $depth=2)
    {
        $this->__typeSelector($type);
        $data = $this->AnalystData->getChildren($this->Auth->user(), $uuid, $depth);
        return $this->RestResponse->viewData($data, 'json');
    }

    public function filterAnalystDataForPush()
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('This function is only accessible via POST requests.'));
        }

        $this->loadModel('AnalystData');

        $allIncomingAnalystData = $this->request->data;
        $allData = $this->AnalystData->filterAnalystDataForPush($allIncomingAnalystData);

        return $this->RestResponse->viewData($allData, $this->response->type());
    }

    public function indexMinimal()
    {
        $this->loadModel('AnalystData');
        $filters = [];
        if ($this->request->is('post')) {
            $filters = $this->request->data;
        }
        $options = [];
        if (!empty($filters['orgc_name'])) {
            $orgcNames = $filters['orgc_name'];
            if (!is_array($orgcNames)) {
                $orgcNames = [$orgcNames];
            }
            $filterName = 'orgc_uuid';
            // Track whether an OR-rule (allow-list) was supplied separately from
            // whether it resolved: a NOT-rule against an org that doesn't exist
            // locally should impose no restriction, not exclude everything. Only
            // "caller asked for specific orgs, none exist" should return nothing.
            $hasOrRule = false;
            foreach ($orgcNames as $orgcName) {
                if (!is_string($orgcName) || $orgcName === '') {
                    continue;
                }
                if ($orgcName[0] === '!') {
                    $orgc = $this->AnalystData->Orgc->fetchOrg(substr($orgcName, 1));
                    if ($orgc === false) {
                        continue;
                    }
                    $options[]['AND'][] = ["{$filterName} !=" => $orgc['uuid']];
                } else {
                    $hasOrRule = true;
                    $orgc = $this->AnalystData->Orgc->fetchOrg($orgcName);
                    if ($orgc === false) {
                        continue;
                    }
                    $options['OR'][] = [$filterName => $orgc['uuid']];
                }
            }

            if ($hasOrRule && empty($options['OR'])) {
                return $this->RestResponse->viewData([], $this->response->type());
            }
        }
        $types = AnalystData::syncTypes($filters['types'] ?? null);
        $allData = $this->AnalystData->indexMinimal($this->Auth->user(), $options, $types);

        return $this->RestResponse->viewData($allData, $this->response->type());
    }

    public function pushAnalystData()
    {
        if (!$this->Auth->user()['Role']['perm_sync'] || !$this->Auth->user()['Role']['perm_analyst_data']) {
            throw new MethodNotAllowedException(__('You do not have the permission to do that.'));
        }
        if (!$this->_isRest()) {
            throw new MethodNotAllowedException(__('This action is only accessible via a REST request.'));
        }
        if ($this->request->is('post')) {
            $this->loadModel('AnalystData');
            $analystData = $this->request->data;
            $saveResult = $this->AnalystData->captureAnalystData($this->Auth->user(), $analystData);
            $messageInfo = __('%s imported, %s ignored, %s failed. %s', $saveResult['imported'], $saveResult['ignored'], $saveResult['failed'], !empty($saveResult['errors']) ? implode(', ', $saveResult['errors']) : '');
            if ($saveResult['success']) {
                $message = __('Analyst Data imported. ') . $messageInfo;
                return $this->RestResponse->saveSuccessResponse('AnalystData', 'pushAnalystData', false, $this->response->type(), $message);
            } else {
                $message = __('Could not import analyst data. ') . $messageInfo;
                return $this->RestResponse->saveFailResponse('AnalystData', 'pushAnalystData', false, $message);
            }
        }
    }

    /**
     * A batched push: a list of {Type: record}, each captured on its own and
     * reported in order (AnalystData::captureBatch).
     */
    public function pushAnalystDataBatch()
    {
        if (!$this->Auth->user()['Role']['perm_sync'] || !$this->Auth->user()['Role']['perm_analyst_data']) {
            throw new MethodNotAllowedException(__('You do not have the permission to do that.'));
        }
        if (!$this->_isRest()) {
            throw new MethodNotAllowedException(__('This action is only accessible via a REST request.'));
        }
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException(__('This action expects a POST request.'));
        }
        $records = $this->request->data;
        if (!is_array($records) || empty($records) || !array_is_list($records)) {
            throw new BadRequestException(__('Expected a non-empty list of analyst data records.'));
        }
        if (count($records) > AnalystData::PUSH_BATCH_COUNT) {
            throw new BadRequestException(__('At most %s records per request.', AnalystData::PUSH_BATCH_COUNT));
        }
        $this->loadModel('AnalystData');
        $report = $this->AnalystData->captureBatch($this->Auth->user(), $records);
        return $this->RestResponse->viewData($report, 'json');
    }

    /**
     * A graph's document is stored as JSON text; REST returns it as an object.
     */
    private function __decodeGraphContent(array $analystData): array
    {
        return $this->__decodeGraphContents([$analystData])[0];
    }

    /**
     * Graph documents as REST returns them: records as stored, module answers
     * only as the requester may see them.
     *
     * @param array $rows
     * @return array
     */
    private function __decodeGraphContents(array $rows): array
    {
        if ($this->modelSelection !== 'Graph') {
            return $rows;
        }
        App::uses('AnalystGraphDocumentTool', 'Tools');
        $documents = [];
        foreach ($rows as $i => $row) {
            if (isset($row['Graph']['content'])) {
                $documents[$i] = AnalystGraphDocumentTool::decode($row['Graph']['content']);
            }
        }
        $documents = ClassRegistry::init('AnalystGraphData')->documentsFor($this->Auth->user(), array_filter($documents), true);
        foreach ($rows as $i => $row) {
            if (isset($row['Graph']['content'])) {
                $rows[$i]['Graph']['content'] = $documents[$i] ?? null;
            }
        }
        return $rows;
    }

    private function __typeSelector($type) {
        foreach ($this->__valid_types as $vt) {
            if ($type === $vt) {
                $this->modelSelection = $vt;
                $this->loadModel($vt);
                $this->AnalystData = $this->{$vt};
                $this->modelClass = $vt;
                $this->{$vt}->current_user = $this->Auth->user();
                if (!empty($this->request->data)) {
                    if (!isset($this->request->data[$type])) {
                        $this->request->data = [$type => $this->request->data];
                    }
                }
                return $vt;
            }
        }
        throw new MethodNotAllowedException(__('Invalid type.'));
    }
}
