<?php
App::uses('AppController', 'Controller');

/**
 * @property ObjectReference $ObjectReference
 */
class ObjectReferencesController extends AppController
{
    public $components = array('RequestHandler', 'Session');

    public function beforeFilter()
    {
        parent::beforeFilter();
        // The event pivot explorer posts hand-built JSON to add(), so it sends
        // the CSRF token as the X-CSRF-Token header instead of _Token fields.
        $this->_csrfTokenHeaderOnly(['add']);
    }

    public $paginate = array(
        'limit' => 20,
        'order' => array(
            'ObjectReference.id' => 'desc'
        ),
    );

    public function add($objectId = false)
    {
        if (empty($objectId)) {
            if ($this->request->is('post') && !empty($this->request->data['object_uuid'])) {
                $objectId = $this->request->data['object_uuid'];
            }
        }
        if (empty($objectId)) {
            throw new NotFoundException('No object defined.');
        }
        if (Validation::uuid($objectId)) {
            $conditions = ['Object.uuid' => $objectId];
        } else {
            $conditions = ['Object.id' => $objectId];
        }
        $conditions['Object.deleted'] = 0;

        $object = $this->ObjectReference->Object->find('first', array(
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array(
                'Event' => array(
                    'fields' => array('Event.id', 'Event.orgc_id', 'Event.user_id', 'Event.extends_uuid')
                )
            )
        ));
        if (empty($object) || !$this->__canModifyEvent($object)) {
            throw new NotFoundException('Invalid object.');
        }
        $this->set('objectId', $object['Object']['id']);
        if ($this->request->is('post')) {
            if (!isset($this->request->data['ObjectReference'])) {
                $this->request->data = array('ObjectReference' => $this->request->data);
            }
            list($referenced_id, $referenced_uuid, $referenced_type) = $this->ObjectReference->getReferencedInfo(trim($this->request->data['ObjectReference']['referenced_uuid']), $object, true, $this->Auth->user());
            $relationship_type = empty($this->request->data['ObjectReference']['relationship_type']) ? '' : $this->request->data['ObjectReference']['relationship_type'];
            if (!empty($this->request->data['ObjectReference']['relationship_type_select']) && $this->request->data['ObjectReference']['relationship_type_select'] !== 'custom') {
                $relationship_type = $this->request->data['ObjectReference']['relationship_type_select'];
            }
            $data = array(
                'referenced_id' => $referenced_id,
                'referenced_uuid' => $referenced_uuid,
                'relationship_type' => $relationship_type,
                'comment' => !empty($this->request->data['ObjectReference']['comment']) ? $this->request->data['ObjectReference']['comment'] : '',
                'event_id' => $object['Event']['id'],
                'object_uuid' => $object['Object']['uuid'],
                'source_uuid' => $object['Object']['uuid'],
                'object_id' => $object['Object']['id'],
                'referenced_type' => $referenced_type,
                'uuid' => CakeText::uuid()
            );
            $object_uuid = $object['Object']['uuid'];
            $this->ObjectReference->create();
            $result = $this->ObjectReference->save(array('ObjectReference' => $data));
            if ($result) {
                $this->ObjectReference->updateTimestamps($data);
                if ($this->_isRest()) {
                    $object = $this->ObjectReference->find("first", array(
                        'recursive' => -1,
                        'conditions' => array('ObjectReference.id' => $this->ObjectReference->id)
                    ));
                    $object['ObjectReference']['object_uuid'] = $object_uuid;
                    return $this->RestResponse->viewData($object, $this->response->type());
                } elseif ($this->request->is('ajax')) {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Object reference added.')),'status'=>200, 'type' => 'json'));
                }
            } else {
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('ObjectReferences', 'add', false, $this->ObjectReference->validationErrors, $this->response->type());
                } elseif ($this->request->is('ajax')) {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Object reference could not be added.')),'status'=>200, 'type' => 'json'));
                }
            }
        } else {
            if ($this->_isRest()) {
                return $this->RestResponse->describe('ObjectReferences', 'add', false, $this->response->type());
            }

            list($event, $relationships) = $this->__referenceChoices(
                $object,
                $object['Object']['id']
            );
            $this->set('relationships', $relationships);
            $this->set('event', $event);
            $this->set('objectId', $object['Object']['id']);
            $this->layout = false;
            $this->render('ajax/add');
        }
    }

    public function delete($id, $hard = false)
    {
        $objectReference = $this->ObjectReference->find('first', array(
            'conditions' => Validation::uuid($id) ? ['ObjectReference.uuid' => $id] : ['ObjectReference.id' => $id],
            'recursive' => -1,
            'contain' => array('Object' => array('Event'))
        ));
        if (empty($objectReference)) {
            throw new NotFoundException(__('Invalid object reference.'));
        }
        if (!$this->__canModifyEvent($objectReference['Object'])) {
            throw new ForbiddenException(__('Invalid object reference.'));
        }
        $id = $objectReference['ObjectReference']['id'];
        if ($this->request->is('post') || $this->request->is('put') || $this->request->is('delete')) {
            $result = $this->ObjectReference->smartDelete($objectReference['ObjectReference']['id'], $hard);
            if ($result === true) {
                if ($this->_isRest()) {
                    return $this->RestResponse->saveSuccessResponse('ObjectReferences', 'delete', $id, $this->response->type());
                } else {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'Object reference deleted.')), 'status'=>200, 'type' => 'json'));
                }
            } else {
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('ObjectReferences', 'delete', $id, $result, $this->response->type());
                } else {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'Object reference was not deleted.')), 'status'=>200, 'type' => 'json'));
                }
            }
        } else {
            if (!$this->request->is('ajax')) {
                throw new MethodNotAllowedException('This action is only accessible via POST request.');
            }
            $this->set('hard', $hard);
            $this->set('id', $id);
            $this->set('event_id', $objectReference['Object']['Event']['id']);
            $this->render('ajax/delete');
        }
    }

    public function view($id)
    {
        $objectReference = $this->ObjectReference->find('first', array(
            'conditions' => Validation::uuid($id) ? ['ObjectReference.uuid' => $id] : ['ObjectReference.id' => $id],
            'recursive' => -1,
        ));
        if (empty($objectReference)) {
            throw new NotFoundException(__('Invalid object reference.'));
        }
        // Check if user can view object that contains this reference
        $object = $this->ObjectReference->Object->fetchObjectSimple($this->Auth->user(), [
            'conditions' => ['Object.id' => $objectReference['ObjectReference']['object_id']],
        ]);
        if (empty($object)) {
            throw new NotFoundException(__('Invalid object reference.'));
        }
        return $this->RestResponse->viewData($objectReference, 'json');
    }

    public function bulkAdd($eventId, $selectedAttributes = '[]')
    {
        if (!$this->request->is('ajax')) {
            throw new MethodNotAllowedException(__('This action can only be reached via AJAX.'));
        }

        $selectedAttributeIDs = $this->_jsonDecode($selectedAttributes);
        $event = $this->ObjectReference->Object->Event->fetchEvent($this->Auth->user(), [
            'eventid' => $eventId,
        ]);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event.'));
        }
        $event = $event[0];
        if (!$this->__canModifyEvent($event)) {
            throw new ForbiddenException(__('You do not have permission to do that.'));
        }

        $selectedAttributes = [];
        foreach ($event['Attribute'] as $attribute) {
            if (in_array($attribute['id'], $selectedAttributeIDs)) {
                $selectedAttributes[$attribute['id']] = $attribute;
            }
        }

        if (empty($selectedAttributes)) {
            throw new BadRequestException(__('No attribute selected.'));
        }

        if ($this->request->is('post')) {
            $conditions = [
                'Object.deleted' => 0,
                'Object.event_id' => $eventId,
                'Object.uuid' => $this->data['ObjectReference']['source_uuid'],
            ];
            $object = $this->ObjectReference->Object->find('first', array(
                'conditions' => $conditions,
                'recursive' => -1,
            ));
            if (empty($object)) {
                throw new NotFoundException('Invalid object.');
            }

            if (!empty($this->request->data['ObjectReference']['relationship_type_select']) && $this->request->data['ObjectReference']['relationship_type_select'] != 'custom') {
                $this->request->data['ObjectReference']['relationship_type'] = $this->request->data['ObjectReference']['relationship_type_select'];
            }
            $successCount = 0;
            foreach ($selectedAttributes as $attributeID => $attribute) {
                $referenced_type = 0; // reference type is always an attribute (for now?)
                $newRelationship = array(
                    'referenced_id' => $attributeID,
                    'referenced_uuid' => $attribute['uuid'],
                    'relationship_type' => $this->request->data['ObjectReference']['relationship_type'],
                    'comment' => !empty($this->request->data['ObjectReference']['comment']) ? $this->request->data['ObjectReference']['comment'] : '',
                    'event_id' => $event['Event']['id'],
                    'object_uuid' => $object['Object']['uuid'],
                    'source_uuid' => $object['Object']['uuid'],
                    'object_id' => $object['Object']['id'],
                    'referenced_type' => $referenced_type,
                    'uuid' => CakeText::uuid()
                );

                $this->ObjectReference->create();
                $result = $this->ObjectReference->save(['ObjectReference' => $newRelationship]);
                if ($result) {
                    $successCount += 1;
                }
            }
            if ($successCount > 0) {
                $this->ObjectReference->updateTimestamps($newRelationship);
                if ($this->_isRest()) {
                    $object = $this->ObjectReference->find('first', [
                        'recursive' => -1,
                        'conditions' => ['ObjectReference.id' => $this->ObjectReference->id]
                    ]);
                    $object['ObjectReference']['object_uuid'] = $object['Object']['uuid'];
                    return $this->RestResponse->viewData($object, $this->response->type());
                } elseif ($this->request->is('ajax')) {
                    $message = __('Added %s Object references.', $successCount);
                    return $this->RestResponse->saveSuccessResponse('ObjectReference', 'bulkAdd', $object['Object']['id'], false, $message);
                }
            } else {
                if ($this->_isRest()) {
                    return $this->RestResponse->saveFailResponse('ObjectReferences', 'bulkAdd', false, $this->ObjectReference->validationErrors, $this->response->type());
                } elseif ($this->request->is('ajax')) {
                    return $this->RestResponse->saveFailResponse('ObjectReferences', 'bulkAdd', $object['Object']['id'], $this->ObjectReference->validationErrors, $this->response->type());
                }
            }
        }

        $eventObjects = [];
        $validSourceUuid = [];
        foreach ($event['Object'] as $object) {
            $validSourceUuid[$object['uuid']] = sprintf('[%s] %s ', $object['id'], $object['name']);
            $eventObjects[$object['uuid']] = $object;
        }

        $this->loadModel('ObjectRelationship');
        $relationships = $this->ObjectRelationship->find('column', array(
            'recursive' => -1,
            'fields' => ['name'],
        ));
        $relationships = array_combine($relationships, $relationships);
        $relationships['custom'] = 'custom';
        ksort($relationships);
        $this->set('relationships', $relationships);
        $this->set('validSourceUuid', $validSourceUuid);
        $this->set('eventObjects', $eventObjects);
        $this->set('selectedAttributes', $selectedAttributes);
        $this->layout = false;
        $this->render('ajax/bulkAdd');
    }

    /**
     * The same choices add() renders, as JSON, for an object that does not exist
     * yet — the add-object form builds its relationships before the object it
     * would hang them off has been saved.
     *
     * @param int $eventId
     * @return CakeResponse
     */
    public function targets($eventId)
    {
        $user = $this->Auth->user();
        $event = $this->ObjectReference->Object->Event->fetchSimpleEvent($user, $eventId, [
            'fields' => ['Event.id', 'Event.orgc_id', 'Event.user_id', 'Event.extends_uuid'],
        ]);
        if (empty($event)) {
            throw new NotFoundException(__('Invalid event.'));
        }
        if (!$this->__canModifyEvent($event)) {
            throw new ForbiddenException(__('You do not have permission to do that.'));
        }

        $eventId = (int)$event['Event']['id'];
        $search = trim((string)($this->request->query('searchTerm') ?? ''));
        $limit = 50;

        $reach = $this->__referenceReachConditions($user, $eventId);

        $objectConditions = ['Object.deleted' => 0, 'Object.event_id' => $eventId];
        $attributeConditions = ['Attribute.deleted' => 0, 'Attribute.event_id' => $eventId];
        if ($reach !== null) {
            $objectConditions[] = $reach['object'];
            $attributeConditions[] = $reach['attribute'];
        }
        if ($search !== '') {
            $like = '%' . $search . '%';
            $objectConditions[] = ['OR' => [
                'Object.name LIKE' => $like,
                'Object.uuid LIKE' => $like,
                'Object.comment LIKE' => $like,
            ]];
            $attributeConditions[] = ['OR' => [
                'Attribute.value1 LIKE' => $like,
                'Attribute.value2 LIKE' => $like,
                'Attribute.uuid LIKE' => $like,
            ]];
        }

        $objects = $this->ObjectReference->Object->find('all', [
            'recursive' => -1,
            'conditions' => $objectConditions,
            'fields' => ['Object.uuid', 'Object.name', 'Object.meta-category'],
            'order' => ['Object.id' => 'desc'],
            'limit' => $limit,
        ]);
        $attributes = $this->ObjectReference->Object->Attribute->find('all', [
            'recursive' => -1,
            'conditions' => $attributeConditions,
            'fields' => ['Attribute.uuid', 'Attribute.value1', 'Attribute.value2',
                         'Attribute.type', 'Attribute.category'],
            'order' => ['Attribute.id' => 'desc'],
            'limit' => $limit,
        ]);

        $targets = [];
        foreach ($objects as $row) {
            $targets[] = [
                'uuid' => $row['Object']['uuid'],
                'kind' => 'object',
                'label' => $row['Object']['name'],
                'context' => $row['Object']['meta-category'],
            ];
        }
        foreach ($attributes as $row) {
            $value = $row['Attribute']['value1'];
            if ($row['Attribute']['value2'] !== '') {
                $value .= '|' . $row['Attribute']['value2'];
            }
            $targets[] = [
                'uuid' => $row['Attribute']['uuid'],
                'kind' => 'attribute',
                'label' => $value,
                'context' => $row['Attribute']['category'] . '/' . $row['Attribute']['type'],
            ];
        }

        $this->loadModel('ObjectRelationship');
        $relationships = $this->ObjectRelationship->find('column', [
            'recursive' => -1,
            'fields' => ['name'],
            'order' => ['name' => 'asc'],
        ]);
        $relationships[] = 'custom';

        return new CakeResponse([
            'body' => json_encode([
                'relationships' => $relationships,
                'targets' => $targets,
                'truncated' => count($objects) >= $limit || count($attributes) >= $limit,
            ]),
            'status' => 200,
            'type' => 'json',
        ]);
    }

    /**
     * What a user may point a reference at, beyond their own event: anything
     * shared with them. Site admins are held to nothing, which is the null.
     *
     * @param array $user
     * @param int $ownEventId
     * @return array|null ['attribute' => …, 'object' => …] OR conditions
     */
    private function __referenceReachConditions(array $user, $ownEventId)
    {
        if (!empty($user['Role']['perm_site_admin'])) {
            return null;
        }
        $sgids = $this->ObjectReference->Object->SharingGroup->authorizedIds($user);
        $shared = array(
            'distribution' => array(1, 2, 3, 5),
        );
        return array(
            'attribute' => array('OR' => array(
                'Attribute.event_id' => $ownEventId,
                'Attribute.distribution' => $shared['distribution'],
                array('Attribute.distribution' => 4, 'Attribute.sharing_group_id' => $sgids),
            )),
            'object' => array('OR' => array(
                'Object.event_id' => $ownEventId,
                'Object.distribution' => $shared['distribution'],
                array('Object.distribution' => 4, 'Object.sharing_group_id' => $sgids),
            )),
        );
    }

    /**
     * Everything the reference form offers: the event's objects and attributes
     * as possible targets, keyed by uuid, and the relationship vocabulary.
     *
     * Shared by add() and targets() so that both answer with exactly the same
     * set — the distribution rules a non site-admin is held to are the point of
     * this, and they must not drift between the two.
     *
     * @param array $object the object the reference starts from, with its Event
     * @param int|false $excludeObjectId an object to leave out, itself for add()
     * @return array [$event, $relationships]
     */
    private function __referenceChoices(array $object, $excludeObjectId = false)
    {
        $user = $this->Auth->user();
        $attributeConditions = array('Attribute.deleted' => 0, 'Attribute.object_id' => 0);
        $objectConditions = array('Object.deleted' => 0);
        if ($excludeObjectId !== false) {
            $objectConditions['NOT'] = array('Object.id' => $excludeObjectId);
        }
        $objectAttributeConditions = array('Attribute.deleted' => 0);
        $reach = $this->__referenceReachConditions($user, (int)$object['Event']['id']);
        if ($reach !== null) {
            $attributeConditions[] = $reach['attribute'];
            $objectConditions[] = $reach['object'];
            $objectAttributeConditions[] = $reach['attribute'];
        }
        $events = $this->ObjectReference->Object->Event->find('all', array(
            'conditions' => array(
                'OR' => array(
                    'Event.id' => $object['Event']['id'],
                    'AND' => array(
                        'Event.uuid' => $object['Event']['extends_uuid'],
                        $this->ObjectReference->Object->Event->createEventConditions($this->Auth->user())
                    )
                ),
            ),
            'recursive' => -1,
            'fields' => array('Event.id'),
            'contain' => array(
                'Attribute' => array(
                    'conditions' => $attributeConditions,
                    'fields' => array('Attribute.id', 'Attribute.uuid', 'Attribute.type', 'Attribute.category', 'Attribute.value', 'Attribute.to_ids')
                ),
                'Object' => array(
                    'conditions' => $objectConditions,
                    'fields' => array('Object.id', 'Object.uuid', 'Object.name', 'Object.meta-category'),
                    'Attribute' => array(
                        'conditions' => $objectAttributeConditions,
                        'fields' => array('Attribute.id', 'Attribute.uuid', 'Attribute.type', 'Attribute.category', 'Attribute.value', 'Attribute.to_ids')
                    )
                )
            )
        ));
        $event = $events[0];
        for ($i = 1; $i < count($events); $i++) {
            $event['Attribute'] = array_merge($event['Attribute'], $events[$i]['Attribute']);
            $event['Object'] = array_merge($event['Object'], $events[$i]['Object']);
        }
        $toRearrange = array('Attribute', 'Object');
        foreach ($toRearrange as $d) {
            if (!empty($event[$d])) {
                $temp = array();
                foreach ($event[$d] as $data) {
                    $temp[$data['uuid']] = $data;
                }
                $event[$d] = $temp;
            }
        }
        $this->loadModel('ObjectRelationship');
        $relationships = $this->ObjectRelationship->find('column', array(
            'recursive' => -1,
            'fields' => ['name'],
        ));
        $relationships = array_combine($relationships, $relationships);
        $relationships['custom'] = 'custom';
        ksort($relationships);
        return [$event, $relationships];
    }

}
