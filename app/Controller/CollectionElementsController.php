<?php
App::uses('AppController', 'Controller');
App::uses('ActiveWorkspaceTool', 'Tools');
App::uses('AnalystData', 'Model');
App::uses('CollectionToEvent', 'Model');
App::uses('NewEventFormTool', 'Tools');

class CollectionElementsController extends AppController
{

    public $components = ['Session', 'RequestHandler'];

    public function beforeFilter()
    {
        parent::beforeFilter();
        // Posted by hand-built AJAX from the collection pickers and the
        // workspace, which send the CSRF token as the X-CSRF-Token header
        // instead of _Token fields.
        $this->_csrfTokenHeaderOnly(['addElementToCollection', 'addItems', 'contains', 'describe', 'eventPlan', 'removeItems', 'toEvent']);
        $this->CollectionElement->current_user = $this->Auth->user();
    }

    /**
     * Add records to a collection in one request, as the workspace names
     * them: {items: [{type, uuid} | {type: 'Value', value}], description?}.
     *
     * @param string $collection Its uuid or id
     */
    public function addItems($collection)
    {
        $this->request->allowMethod(['post']);
        $user = $this->Auth->user();
        $target = $this->__editableCollection($user, $collection);
        $description = $this->request->data['description'] ?? '';
        if (!is_string($description)) {
            throw new BadRequestException(__('A description is text.'));
        }
        $report = $this->CollectionElement->addItems($user, $target['id'], $this->__items(), $description);
        ActiveWorkspaceTool::used($user, $target['uuid']);
        return $this->RestResponse->viewData($this->__itemsAnswer($target, $report, !empty($report['added'])), 'json');
    }

    /**
     * Take records out of a collection, named as addItems() takes them or by
     * the keys it answers with.
     *
     * @param string $collection Its uuid or id
     */
    public function removeItems($collection)
    {
        $this->request->allowMethod(['post']);
        $target = $this->__editableCollection($this->Auth->user(), $collection);
        $report = $this->CollectionElement->removeItems($target['id'], $this->__items());
        return $this->RestResponse->viewData($this->__itemsAnswer($target, $report, !empty($report['removed'])), 'json');
    }

    /**
     * Say why the collection holds a record: {item, description}, the item
     * named as addItems() takes it. One line; empty clears it.
     *
     * @param string $collection Its uuid or id
     */
    public function describe($collection)
    {
        $this->request->allowMethod(['post']);
        $target = $this->__editableCollection($this->Auth->user(), $collection);
        $description = $this->request->data['description'] ?? null;
        if (!is_string($description)) {
            throw new BadRequestException(__('A description is text.'));
        }
        $description = trim(preg_replace('/\s+/u', ' ', $description));
        if (mb_strlen($description) > CollectionElement::WHY_LENGTH) {
            throw new BadRequestException(__('Say why in at most %s characters.', CollectionElement::WHY_LENGTH));
        }
        $item = $this->request->data['item'] ?? null;
        if (CollectionElement::itemTarget($item) === null) {
            throw new BadRequestException(__('Not a record a collection can hold.'));
        }
        $key = $this->CollectionElement->describeItem($target['id'], $item, $description);
        if ($key === null) {
            throw new NotFoundException(__('“%s” does not hold this record.', $target['name']));
        }
        return $this->RestResponse->viewData($this->__itemsAnswer($target, ['key' => $key, 'description' => $description], true), 'json');
    }

    /**
     * Which of these records the collection holds, named as addItems() takes
     * them: {present: [key], absent: [key]}. Changes nothing.
     *
     * @param string $collection Its uuid or id
     */
    public function contains($collection)
    {
        $this->request->allowMethod(['post']);
        $user = $this->Auth->user();
        $target = $this->__editableCollection($user, $collection);
        $report = $this->CollectionElement->heldItems($user, $target['id'], $this->__items());
        return $this->RestResponse->viewData(['collection_uuid' => $target['uuid']] + $report, 'json');
    }

    /**
     * What a selection of the collection would become in an event: {items,
     * event_id} for an event the user may modify, or {items, distribution,
     * sharing_group_id} for a new one, which also answers the form's choices.
     *
     * @param string $collection Its uuid or id
     */
    public function eventPlan($collection)
    {
        $this->request->allowMethod(['post']);
        $user = $this->Auth->user();
        $target = $this->__editableCollection($user, $collection);
        $items = $this->__wayOutItems();
        $data = $this->request->data;
        if (isset($data['event_id'])) {
            list($eventTarget, $rights) = $this->__existingEvent($user, $data['event_id']);
        } else {
            $distribution = $data['distribution'] ?? Configure::read('MISP.default_event_distribution') ?? 0;
            if (!is_scalar($distribution) || !in_array((int)$distribution, [0, 1, 2, 3, 4], true)) {
                throw new BadRequestException(__('A distribution is 0 to 4.'));
            }
            $eventTarget = ['distribution' => (int)$distribution, 'sharing_group_id' => $data['sharing_group_id'] ?? null];
            $rights = $this->__wayOutRights($user, null);
        }
        $this->loadModel('CollectionToEvent');
        $plan = $this->CollectionToEvent->plan($user, $target, $items, $eventTarget, $rights);
        if (!isset($data['event_id'])) {
            $plan['form'] = $this->__newEventForm($user, $target);
        }
        return $this->RestResponse->viewData(['collection_uuid' => $target['uuid']] + $plan, 'json');
    }

    /**
     * Make an event of a selection of the collection, or add it to one:
     * {items, event {info, date, distribution, sharing_group_id,
     * threat_level_id, analysis} | event_id, graph?}. Each item may carry
     * the attribute_type, category, to_ids and comment of what it becomes,
     * and the graph node it is drawn as. What is made for a member MISP did
     * not hold takes its place, in the collection and on `graph`, the
     * workspace graph, when the user may write it.
     *
     * @param string $collection Its uuid or id
     */
    public function toEvent($collection)
    {
        $this->request->allowMethod(['post']);
        $user = $this->Auth->user();
        $target = $this->__editableCollection($user, $collection);
        $items = $this->__wayOutItems();
        $data = $this->request->data;
        if (isset($data['event_id'])) {
            list($eventTarget, $rights) = $this->__existingEvent($user, $data['event_id']);
        } else {
            $this->loadModel('Event');
            list($fields, $errors) = NewEventFormTool::fields($user, $data['event'] ?? null, $this->Event);
            if (!empty($errors)) {
                return $this->__refused($errors);
            }
            $eventTarget = ['fields' => $fields];
            $rights = $this->__wayOutRights($user, null);
        }
        $graph = $this->__workspaceGraph($user, $target, $data['graph'] ?? null);
        $this->loadModel('CollectionToEvent');
        $result = $this->CollectionToEvent->apply($user, $target, $items, $eventTarget, $rights, $graph);
        if (isset($result['errors'])) {
            return $this->__refused($result['errors']);
        }
        $result['event']['url'] = Configure::read('MISP.baseurl') . '/events/view/' . $result['event']['id'];
        ActiveWorkspaceTool::used($user, $target['uuid']);
        $now = $this->CollectionElement->Collection->workspaceSummaries($user, ['Collection.id' => $target['id']], 1)[0] ?? $target;
        return $this->RestResponse->viewData([
            'collection_uuid' => $target['uuid'],
            'element_count' => $now['element_count'],
            'Collection' => $now,
        ] + $result, 'json');
    }

    /**
     * The events a selection of the collection may go into: {tied, found},
     * those the collection holds first, then the newest or those matching
     * `q` (an id, a uuid or words of the info).
     *
     * @param string $collection Its uuid or id
     */
    public function eventChoices($collection)
    {
        $this->request->allowMethod(['get']);
        $user = $this->Auth->user();
        $target = $this->__editableCollection($user, $collection);
        $q = $this->request->query['q'] ?? '';
        if (!is_string($q) || mb_strlen($q) > 255) {
            throw new BadRequestException(__('Search with at most 255 characters.'));
        }
        $this->loadModel('CollectionToEvent');
        return $this->RestResponse->viewData(
            ['collection_uuid' => $target['uuid']] + $this->CollectionToEvent->choices($user, $target, $q),
            'json'
        );
    }

    /**
     * @param array $user
     * @param mixed $ref An event's id or uuid
     * @return array [{event: row}, rights]
     * @throws NotFoundException|ForbiddenException
     */
    private function __existingEvent(array $user, $ref)
    {
        $this->loadModel('Event');
        $event = is_scalar($ref) ? $this->Event->fetchSimpleEvent($user, (string)$ref) : null;
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event.'));
        }
        if (!$this->ACL->canModifyEvent($user, $event)) {
            throw new ForbiddenException(__('You cannot add to the event “%s”.', $event['Event']['info']));
        }
        return [['event' => $event], $this->__wayOutRights($user, $event)];
    }

    /**
     * @param array $user
     * @param array|null $event null for a new event of the user's
     * @return array {tag, link}
     */
    private function __wayOutRights(array $user, $event)
    {
        if ($event === null) {
            $role = $user['Role'];
            $tag = !empty($role['perm_site_admin'])
                || ((!empty($role['perm_tagger']) || !empty($role['perm_sync'])) && (!empty($role['perm_modify_org']) || !empty($role['perm_modify'])));
        } else {
            $tag = $this->ACL->canModifyTag($user, $event);
        }
        return ['tag' => $tag, 'link' => $this->ACL->canUserAccess($user, 'analystData', 'add')];
    }

    /**
     * The workspace graph to lay the new records out on, when the user may
     * write it.
     *
     * @param array $user
     * @param array $collection
     * @param mixed $uuid
     * @return array|null {id, uuid}
     * @throws BadRequestException
     */
    private function __workspaceGraph(array $user, array $collection, $uuid)
    {
        if ($uuid === null || $uuid === '') {
            return null;
        }
        if (!is_string($uuid) || !Validation::uuid($uuid)) {
            throw new BadRequestException(__('Name the graph by its uuid.'));
        }
        if (!$this->ACL->canUserAccess($user, 'analystGraphs', 'save')) {
            return null;
        }
        $Graph = ClassRegistry::init('Graph');
        $Graph->current_user = $user;
        $graph = $Graph->find('first', [
            'conditions' => ['AND' => [
                ['Graph.uuid' => array_values(array_unique([$uuid, strtolower($uuid), strtoupper($uuid)]))],
                $Graph->buildConditions($user),
            ]],
            'contain' => ['Org', 'Orgc'],
        ]);
        if (empty($graph) || $graph['Graph']['object_type'] !== 'Collection'
            || strtolower($graph['Graph']['object_uuid']) !== strtolower($collection['uuid'])
        ) {
            throw new BadRequestException(__('That graph is not on “%s”.', $collection['name']));
        }
        if (empty($graph['Graph']['_canEdit'])) {
            return null;
        }
        return ['id' => (int)$graph['Graph']['id'], 'uuid' => strtolower($graph['Graph']['uuid'])];
    }

    /**
     * What the new event's form offers, at the instance's defaults.
     *
     * @param array $user
     * @param array $collection
     * @return array
     */
    private function __newEventForm(array $user, array $collection)
    {
        $this->loadModel('Event');
        $sharingGroups = $this->Event->SharingGroup->fetchAllAuthorised($user, 'name', 1);
        $distributions = $this->Event->distributionLevels;
        if (empty($sharingGroups)) {
            unset($distributions[4]);
        }
        $threatLevels = array_column($this->Event->ThreatLevel->find('all', ['recursive' => -1]), 'ThreatLevel');
        $distribution = (int)(Configure::read('MISP.default_event_distribution') ?? 0);
        return [
            'defaults' => [
                'info' => $collection['name'],
                'date' => date('Y-m-d'),
                'distribution' => isset($distributions[$distribution]) ? $distribution : 0,
                'threat_level_id' => (int)(Configure::read('MISP.default_event_threat_level') ?: 4),
                'analysis' => 0,
            ],
            'distributions' => $distributions,
            'sharing_groups' => $sharingGroups,
            'threat_levels' => array_column($threatLevels, 'name', 'id'),
            'analysis_levels' => $this->Event->analysisLevels,
        ];
    }

    /**
     * @return array
     * @throws BadRequestException
     */
    private function __wayOutItems()
    {
        $items = $this->request->data['items'] ?? null;
        if (!is_array($items) || empty($items) || array_keys($items) !== range(0, count($items) - 1)) {
            throw new BadRequestException(__('A list of items is required.'));
        }
        if (count($items) > CollectionToEvent::ITEM_LIMIT) {
            throw new BadRequestException(__('At most %s items go into an event at once.', CollectionToEvent::ITEM_LIMIT));
        }
        return $items;
    }

    /**
     * @param array $errors field => message
     * @return CakeResponse
     */
    private function __refused(array $errors)
    {
        $response = $this->RestResponse->viewData(['errors' => $errors], 'json');
        $response->statusCode(400);
        return $response;
    }

    /**
     * @param array $user
     * @param string $ref A collection's uuid or id
     * @return array Collection::workspaceSummaries()'s
     * @throws NotFoundException|ForbiddenException
     */
    private function __editableCollection(array $user, $ref)
    {
        if (Validation::uuid($ref)) {
            $condition = ['Collection.uuid' => array_values(array_unique([$ref, strtolower($ref), strtoupper($ref)]))];
        } elseif (ctype_digit((string)$ref)) {
            $condition = ['Collection.id' => (string)$ref];
        } else {
            throw new NotFoundException(__('Invalid %s.', 'Collection'));
        }
        $found = $this->CollectionElement->Collection->workspaceSummaries($user, $condition, 1);
        if (empty($found)) {
            throw new NotFoundException(__('Invalid %s.', 'Collection'));
        }
        if (!$found[0]['_canEdit']) {
            throw new ForbiddenException(__('You cannot change the collection “%s”.', $found[0]['name']));
        }
        return $found[0];
    }

    /**
     * @return array
     * @throws BadRequestException
     */
    private function __items()
    {
        $items = $this->request->data['items'] ?? null;
        if (!is_array($items) || empty($items) || array_keys($items) !== range(0, count($items) - 1)) {
            throw new BadRequestException(__('A list of items is required.'));
        }
        if (count($items) > CollectionElement::ITEM_LIMIT) {
            throw new BadRequestException(__('At most %s items at once.', CollectionElement::ITEM_LIMIT));
        }
        return $items;
    }

    /**
     * @param array $collection
     * @param array $report
     * @param bool $changed
     * @return array With `Collection` as it stands after the change, so a
     *               chip can say how many members it has and what partners
     *               do not have yet
     */
    private function __itemsAnswer(array $collection, array $report, $changed)
    {
        $now = $this->CollectionElement->Collection->workspaceSummaries($this->Auth->user(), ['Collection.id' => $collection['id']], 1)[0] ?? $collection;
        return [
            'collection_uuid' => $collection['uuid'],
            'changed' => $changed,
            'element_count' => $now['element_count'],
            'Collection' => $now,
        ] + $report;
    }

    public $paginate = [
        'limit' => 60,
        'order' => []
    ];

    public $uses = [
    ];

    /**
     * @param mixed $raw one address or a list of them
     * @param string|null $elementType
     * @return array trimmed, de-duplicated addresses; SHA-256s lowercased
     */
    private function __normaliseElementAddresses($raw, $elementType)
    {
        $bySha256 = in_array($elementType, AnalystData::SHA256_TARGETS, true);
        $addresses = [];
        foreach ((array)$raw as $address) {
            if (!is_scalar($address)) {
                continue;
            }
            $address = trim((string)$address);
            if ($address !== '') {
                $addresses[] = $bySha256 ? strtolower($address) : $address;
            }
        }

        return array_values(array_unique($addresses));
    }

    public function add($collection_id)
    {   
        $this->CollectionElement->Collection->current_user = $this->Auth->user();
        if (!$this->CollectionElement->Collection->mayView($this->Auth->user('id'), intval($collection_id))) {
            throw new NotFoundException(__('Invalid %s.', 'Collection'));
        }
        if (!$this->CollectionElement->Collection->mayModify($this->Auth->user('id'), intval($collection_id))) {
            throw new MethodNotAllowedException(__('Invalid Collection or insufficient privileges'));
        }
        $this->CRUD->add([
            'redirect' => ['controller' => 'collections', 'action' => 'view', $collection_id],
            'beforeSave' => function (array $collectionElement) use ($collection_id) {
                // Guard the sink: this callback sees the exact row CRUD::add()
                // is about to save, on both the form and the REST path.
                $type = $collectionElement['CollectionElement']['element_type'] ?? null;
                $column = AnalystData::addressColumn($type, 'element');
                // The form names a value by its text
                $text = $collectionElement['CollectionElement']['value'] ?? null;
                if ($column === 'element_sha256' && empty($collectionElement['CollectionElement'][$column]) && is_string($text) && trim($text) !== '') {
                    $collectionElement['CollectionElement'][$column] = hash('sha256', trim($text));
                }
                unset($collectionElement['CollectionElement']['value']);
                $this->CollectionElement->assertTargetsUsable(
                    $this->Auth->user(),
                    $type,
                    $this->__normaliseElementAddresses($collectionElement['CollectionElement'][$column] ?? null, $type)
                );
                $collectionElement['CollectionElement']['collection_id'] = intval($collection_id);
                return $collectionElement;
            }
        ]);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
        $dropdownData = [
            'types' => array_combine($this->CollectionElement->valid_types, $this->CollectionElement->valid_types)
        ];
        $this->set(compact('dropdownData'));
        $this->set('menuData', array('menuList' => 'collections', 'menuItem' => 'add_element'));
        if($this->theme === "Overmind"){
            $this->layout = false;
        }
    }

    public function delete($element_id)
    {
        $collectionElement = $this->CollectionElement->find('first', [
            'recursive' => -1,
            'conditions' => [
                'CollectionElement.id' => $element_id
            ]
        ]);
        if (empty($collectionElement)) {
            throw new NotFoundException(__('Invalid %s.', 'Collection'));
        }
        $collection_id = $collectionElement['CollectionElement']['collection_id'];
        if (!$this->CollectionElement->Collection->mayView($this->Auth->user('id'), $collection_id)) {
            throw new NotFoundException(__('Invalid %s.', 'Collection'));
        }
        if (!$this->CollectionElement->Collection->mayModify($this->Auth->user('id'), $collection_id)) {
            throw new MethodNotAllowedException(__('Invalid Collection or insufficient privileges'));
        }
        $this->CRUD->delete($element_id, [
            'redirect' => ['controller' => 'collections', 'action' => 'view', $collection_id]
        ]);
        if ($this->restResponsePayload) {
            return $this->restResponsePayload;
        }
    }

    public function deleteSelection($id = null)
    {
        return $this->CRUD->deleteSelection($id, [
            'modelName' => 'CollectionElement',
            'restName' => 'CollectionElements',
            'itemName' => 'element',
            'view' => 'ajax/collectionElementsDeleteConfirmationForm',
            'checkModifyCallback' => function($itemId, $item) {
                // DPT-3: authorise against the element's OWN collection,
                // not a collection whose id happens to equal the element
                // id. mayModify() expects a collection_id, but $itemId is
                // the element id - the bare call gated on the wrong entity,
                // allowing cross-collection / cross-org element deletion.
                // Mirror the single delete() action, using the loaded row.
                $collectionId = $item['CollectionElement']['collection_id'];
                return $this->CollectionElement->Collection->mayModify($this->Auth->user('id'), $collectionId);
            },
            'multiSuccessMessageCallback' => function($count) {
                return __n('%s element deleted.', '%s elements deleted.', $count, $count);
            }
        ]);
    }

    public function index($collection_id)
    {
        $this->set('menuData', array('menuList' => 'collections', 'menuItem' => 'index'));
        if (!$this->CollectionElement->Collection->mayView($this->Auth->user('id'), intval($collection_id))) {
            throw new NotFoundException(__('Invalid collection or no access.'));
        }
        $params = [
            'filters' => ['uuid', 'type', 'name'],
            'quickFilters' => ['name'],
            'conditions' => ['collection_id' => $collection_id]
        ];
        $this->loadModel('Event');
        $this->set('distributionLevels', $this->Event->distributionLevels);
        $this->CRUD->index($params);
        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
    }

    /**
     * For an AttributeValue element the second segment is the SHA-256 of the
     * value's text; for every other type it is the element's UUID.
     */
    public function addElementToCollection($element_type, $element_uuid)
    {
        if (!in_array($element_type, $this->CollectionElement->valid_types, true)) {
            throw new NotFoundException(__('Invalid element type.'));
        }
        $column = AnalystData::addressColumn($element_type, 'element');
        $isOvermind = $this->theme === 'Overmind';
        if ($isOvermind && $this->request->is('ajax')) {
            $this->layout = false;
        }
        if ($this->request->is('get')) {
            $validCollections = $this->CollectionElement->Collection->find('list', [
                'recursive' => -1,
                'fields' => ['Collection.id', 'Collection.name'],
                'conditions' => ['Collection.orgc_id' => $this->Auth->user('org_id')],
                'order' => ['Collection.name' => 'ASC']
            ]);
            if (empty($validCollections) && !$isOvermind) {
                if ($this->request->is('ajax')) {
                    return $this->redirect(['controller' => 'collections', 'action' => 'add']);
                }
                throw new NotFoundException(__('You don\'t have any collections yet. Make sure you create one first before you can start adding elements.'));
            }
            /*
             * Grey out collections that already contain this element instead of
             * hiding them, since the modal lists collections by name and a missing
             * entry would look like it was removed.
             */
            $alreadyIn = [];
            if (!empty($validCollections)) {
                $alreadyIn = array_values(array_unique($this->CollectionElement->find('list', [
                    'recursive' => -1,
                    'fields' => ['CollectionElement.id', 'CollectionElement.collection_id'],
                    'conditions' => [
                        'CollectionElement.element_type' => $element_type,
                        'CollectionElement.' . $column => $this->__normaliseElementAddresses($element_uuid, $element_type),
                        'CollectionElement.collection_id' => array_keys($validCollections)
                    ]
                ])));
            }
            $dropdownData = [
                'collections' => $validCollections
            ];
            $this->set(compact('dropdownData'));
            $this->set('alreadyInCollectionIds', $alreadyIn);
            $this->set('elementType', $element_type);
            $this->set('elementUuid', $element_uuid);
            $target = $this->CollectionElement->attachTargets($this->Auth->user(), [
                ['element_type' => $element_type, $column => current($this->__normaliseElementAddresses($element_uuid, $element_type))],
            ]);
            $this->set('elementValue', $target[0]['AttributeValue']['value'] ?? null);
        } else if ($this->request->is('post')) {
            if (!isset($this->request->data['CollectionElement'])) {
                $this->request->data = ['CollectionElement' => $this->request->data];
            }
            if (!isset($this->request->data['CollectionElement']['collection_id'])) {
                throw new NotFoundException(__('No collection_id specified.'));
            }
            $collection_id = intval($this->request->data['CollectionElement']['collection_id']);
            if (!$this->CollectionElement->Collection->mayModify($this->Auth->user('id'), $collection_id)) {
                throw new NotFoundException(__('Invalid collection or not authorized.'));
            }
            $description = empty($this->request->data['CollectionElement']['description']) ? '' : $this->request->data['CollectionElement']['description'];
            $elementUuids = $this->__normaliseElementAddresses($this->request->data['CollectionElement'][$column] ?? $element_uuid, $element_type);
            if (empty($elementUuids)) {
                throw new NotFoundException(__('No element UUID specified.'));
            }
            $this->CollectionElement->assertTargetsUsable($this->Auth->user(), $element_type, $elementUuids);

            $result = true;
            $duplicateCount = 0;
            foreach ($elementUuids as $currentElementUuid) {
                $dataToSave = [
                    'CollectionElement' => [
                        $column => $currentElementUuid,
                        'element_type' => $element_type,
                        'description' => $description,
                        'collection_id' => $collection_id
                    ]
                ];
                $this->CollectionElement->create();
                try {
                    $saveResult = $this->CollectionElement->save($dataToSave);
                    if (!$saveResult) {
                        $result = false;
                        break;
                    }
                } catch (PDOException $e) {
                    if (CollectionElement::isDuplicate($e)) {
                        $duplicateCount++;
                    } else {
                        throw $e;
                    }
                }
            }

            if ($result) {
                $added = count($elementUuids) - $duplicateCount;
                if (count($elementUuids) === 1) {
                    $message = $duplicateCount
                        ? __('Element already in the Collection.')
                        : __('Element added to the Collection.');
                } else {
                    $message = __n('%s element added to the Collection.', '%s elements added to the Collection.', $added, $added);
                    if ($duplicateCount > 0) {
                        $message .= ' ' . __n('%s was already in it.', '%s were already in it.', $duplicateCount, $duplicateCount);
                    }
                }
                if ($this->IndexFilter->isRest()) {
                    return $this->RestResponse->saveSuccessResponse('CollectionElements', 'addElementToCollection', false, $this->response->type(), $message);
                } else {
                    $this->Flash->success($message);
                    $this->redirect(Router::url($this->referer(), true));
                }
            } else {
                $message = __('Element could not be added to the Collection.');
                if ($this->IndexFilter->isRest()) {
                    return $this->RestResponse->saveFailResponse('CollectionElements', 'addElementToCollection', false, $this->CollectionElement->validationErrors ?: $message, $this->response->type());
                } else {
                    $this->Flash->error($message);
                    $this->redirect(Router::url($this->referer(), true));
                }
            }
        }
    }
}
