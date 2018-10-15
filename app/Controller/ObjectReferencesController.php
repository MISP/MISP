<?php

App::uses('AppController', 'Controller');

class ObjectReferencesController extends AppController
{
    public $components = array('Security' ,'RequestHandler', 'Session');

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
            throw new MethodNotAllowedException('No object defined.');
        }
        if (Validation::uuid($objectId)) {
            $temp = $this->ObjectReference->Object->find('first', array(
                'recursive' => -1,
                'fields' => array('Object.id'),
                'conditions' => array('Object.uuid' => $objectId, 'Object.deleted' => 0)
            ));
            if (empty($temp)) {
                throw new NotFoundException('Invalid Object');
            }
            $objectId = $temp['Object']['id'];
        } elseif (!is_numeric($objectId)) {
            throw new NotFoundException(__('Invalid object'));
        }
        $object = $this->ObjectReference->Object->find('first', array(
            'conditions' => array('Object.id' => $objectId, 'Object.deleted' => 0),
            'recursive' => -1,
            'contain' => array(
                'Event' => array(
                    'fields' => array('Event.id', 'Event.orgc_id')
                )
            )
        ));
        if (empty($object) || (!$this->_isSiteAdmin() && $object['Event']['orgc_id'] != $this->Auth->user('org_id'))) {
            throw new MethodNotAllowedException('Invalid object.');
        }
        $this->set('objectId', $objectId);
        if ($this->request->is('post')) {
            $data = array();
            if (!isset($this->request->data['ObjectReference'])) {
                $this->request->data['ObjectReference'] = $this->request->data;
            }
            $referenced_type = 1;
            $target_object = $this->ObjectReference->Object->find('first', array(
                'conditions' => array('Object.uuid' => $this->request->data['ObjectReference']['referenced_uuid'], 'Object.deleted' => 0),
                'recursive' => -1,
                'fields' => array('Object.id', 'Object.uuid', 'Object.event_id')
            ));
            if (!empty($target_object)) {
                $referenced_id = $target_object['Object']['id'];
                $referenced_uuid = $target_object['Object']['uuid'];
                if ($target_object['Object']['event_id'] != $object['Event']['id']) {
                    throw new NotFoundException('Invalid target. Target has to be within the same event.');
                }
            } else {
                $target_attribute = $this->ObjectReference->Object->Attribute->find('first', array(
                    'conditions' => array('Attribute.uuid' => $this->request->data['ObjectReference']['referenced_uuid'], 'Attribute.deleted' => 0),
                    'recursive' => -1,
                    'fields' => array('Attribute.id', 'Attribute.uuid', 'Attribute.event_id')
                ));
                if (empty($target_attribute)) {
                    throw new NotFoundException('Invalid target.');
                }
                if ($target_attribute['Attribute']['event_id'] != $object['Event']['id']) {
                    throw new NotFoundException('Invalid target. Target has to be within the same event.');
                }
                $referenced_id = $target_attribute['Attribute']['id'];
                $referenced_uuid = $target_attribute['Attribute']['uuid'];
                $referenced_type = 0;
            }
            $relationship_type = empty($this->request->data['ObjectReference']['relationship_type']) ? '' : $this->request->data['ObjectReference']['relationship_type'];
            if (!empty($this->request->data['ObjectReference']['relationship_type_select']) && $this->request->data['ObjectReference']['relationship_type_select'] !== 'custom') {
                $relationship_type = $this->request->data['ObjectReference']['relationship_type_select'];
            }
            $data = array(
                'referenced_type' => $referenced_type,
                'referenced_id' => $referenced_id,
                'referenced_uuid' => $referenced_uuid,
                'relationship_type' => $relationship_type,
                'comment' => !empty($this->request->data['ObjectReference']['comment']) ? $this->request->data['ObjectReference']['comment'] : '',
                'event_id' => $object['Event']['id'],
                'object_uuid' => $object['Object']['uuid'],
                'object_id' => $objectId,
                'referenced_type' => $referenced_type,
                'uuid' => CakeText::uuid()
            );
            $this->ObjectReference->create();
            $result = $this->ObjectReference->save(array('ObjectReference' => $data));
            if ($result) {
                $this->ObjectReference->updateTimestamps($this->id, $data);
                if ($this->_isRest()) {
                    $object = $this->ObjectReference->find("first", array(
                        'recursive' => -1,
                        'conditions' => array('ObjectReference.id' => $this->ObjectReference->id)
                    ));
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
            } else {
                $event = $this->ObjectReference->Object->Event->find('first', array(
                    'conditions' => array('Event.id' => $object['Event']['id']),
                    'recursive' => -1,
                    'fields' => array('Event.id'),
                    'contain' => array(
                        'Attribute' => array(
                            'conditions' => array('Attribute.deleted' => 0, 'Attribute.object_id' => 0),
                            'fields' => array('Attribute.id', 'Attribute.uuid', 'Attribute.type', 'Attribute.category', 'Attribute.value', 'Attribute.to_ids')
                        ),
                        'Object' => array(
                            'conditions' => array('NOT' => array('Object.id' => $objectId), 'Object.deleted' => 0),
                            'fields' => array('Object.id', 'Object.uuid', 'Object.name', 'Object.meta-category'),
                            'Attribute' => array(
                                'conditions' => array('Attribute.deleted' => 0),
                                'fields' => array('Attribute.id', 'Attribute.uuid', 'Attribute.type', 'Attribute.category', 'Attribute.value', 'Attribute.to_ids')
                            )
                        )
                    )
                ));
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
                $relationshipsTemp = $this->ObjectRelationship->find('all', array(
                    'recursive' => -1
                ));
                $relationships = array();
                $relationshipMetadata = array();
                foreach ($relationshipsTemp as $k => $v) {
                    $relationshipMetadata[$v['ObjectRelationship']['name']] = $v;
                    $relationships[$v['ObjectRelationship']['name']] = $v['ObjectRelationship']['name'];
                }
                $relationships['custom'] = 'custom';
                $this->set('relationships', $relationships);
                $this->set('event', $event);
                $this->set('objectId', $objectId);
                $this->layout = 'ajax';
                $this->render('ajax/add');
            }
        }
    }

    public function delete($id, $hard = false)
    {
        if (Validation::uuid($id)) {
            $temp = $this->ObjectReference->find('first', array(
                'recursive' => -1,
                'fields' => array('ObjectReference.id'),
                'conditions' => array('ObjectReference.uuid' => $id)
            ));
            if (empty($temp)) {
                throw new NotFoundException('Invalid object reference');
            }
            $id = $temp['ObjectReference']['id'];
        } elseif (!is_numeric($id)) {
            throw new NotFoundException(__('Invalid object reference'));
        }
        $objectReference = $this->ObjectReference->find('first', array(
            'conditions' => array('ObjectReference.id' => $id),
            'recursive' => -1,
            'contain' => array('Object' => array('Event'))
        ));
        if (empty($objectReference)) {
            throw new MethodNotAllowedException('Invalid object reference.');
        }
        if (!$this->_isSiteAdmin() && $this->Auth->user('org_id') != $objectReference['Object']['Event']['orgc_id']) {
            throw new MethodNotAllowedException('Invalid object reference.');
        }
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
    }
}
