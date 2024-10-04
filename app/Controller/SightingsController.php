<?php
App::uses('AppController', 'Controller');

/**
 * @property Sighting $Sighting
 * @property Event $Event
 */
class SightingsController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
        'limit' => 60,
        'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
        'order' => array('Sighting.date_sighting' => 'DESC'),
    );

    // takes an attribute ID or UUID
    public function add($id = false)
    {
        if ($this->request->is('post')) {
            $now = time();
            $values = false;
            $timestamp = false;
            $error = false;
            if ($id === 'stix') {
                $result = $this->Sighting->handleStixSighting(file_get_contents('php://input'));
                if ($result['success']) {
                    $result['data'] = json_decode($result['data'], true);
                    $timestamp = isset($result['data']['timestamp']) ? strtotime($result['data']['timestamp']) : $now;
                    $type = '0';
                    $source = '';
                    if (isset($result['data']['values'])) {
                        $values = $result['data']['values'];
                    } else {
                        $error = 'No valid values found that could be extracted from the sightings document.';
                    }
                } else {
                    $error = $result['message'];
                }
            } else {
                if (isset($this->request->data['request'])) {
                    $this->request->data = $this->request->data['request'];
                }
                if (isset($this->request->data['Sighting'])) {
                    $this->request->data = $this->request->data['Sighting'];
                }
                if (!empty($this->request->data['date']) && !empty($this->request->data['time'])) {
                    $timestamp = DateTime::createFromFormat('Y-m-d:H:i:s', $this->request->data['date'] . ':' . $this->request->data['time']);
                    $timestamp = $timestamp->getTimestamp();
                } else {
                    $timestamp = isset($this->request->data['timestamp']) ? $this->request->data['timestamp'] : $now;
                }
                if (isset($this->request->data['value'])) {
                    $this->request->data['values'] = array($this->request->data['value']);
                }
                $values = isset($this->request->data['values']) ? $this->request->data['values'] : false;
                if (!$id && isset($this->request->data['uuid'])) {
                    $id = $this->request->data['uuid'];
                }
                if (!$id && isset($this->request->data['id'])) {
                    $id = $this->request->data['id'];
                }
                $type = isset($this->request->data['type']) ? $this->request->data['type'] : '0';
                $source = isset($this->request->data['source']) ? trim($this->request->data['source']) : '';
                $filters = !empty($this->request->data['filters']) ? $this->request->data['filters'] : false;
            }
            if (!$error) {
                $publish_sighting = !empty(Configure::read('Sightings_enable_realtime_publish'));
                $result = $this->Sighting->saveSightings($id, $values, $timestamp, $this->Auth->user(), $type, $source, false, $publish_sighting, false, $filters);
            }
            if (!is_numeric($result)) {
                $error = $result;
            }
            if ($this->request->is('ajax')) {
                if ($error) {
                    $error_message = 'Could not add the Sighting. Reason: ' . $error;
                    return new CakeResponse(array('body' => json_encode(array('saved' => false, 'errors' => $error_message)), 'status' => 200, 'type' => 'json'));
                } else {
                    return new CakeResponse(array('body' => json_encode(array('saved' => true, 'success' => $result . ' ' . Sighting::TYPE[$type] . (($result == 1) ? '' : 's') . '  added.')), 'status' => 200, 'type' => 'json'));
                }
            } else {
                if ($error) {
                    $error_message = __('Could not add the Sighting. Reason: ') . $error;
                    if ($this->_isRest() || $this->response->type() === 'application/json') {
                        $this->set('message', $error_message);
                        $this->set('_serialize', array('message'));
                    } else {
                        $this->Flash->error($error_message);
                        $this->redirect($this->referer());
                    }
                } else {
                    if ($this->_isRest() || $this->response->type() === 'application/json') {
                        $sighting = $this->Sighting->find('first', array('conditions' => array('Sighting.id' => $this->Sighting->id), 'recursive' => -1));
                        return $this->RestResponse->viewData($sighting, $this->response->type());
                    } else {
                        $this->Flash->success(__('Sighting added'));
                        $this->redirect($this->referer());
                    }
                }
            }
        } else {
            if ($this->_isRest()) {
                return $this->RestResponse->describe('Sightings', 'add', false, $this->response->type());
            }
            if (!$this->request->is('ajax')) {
                throw new MethodNotAllowedException('This method is only accessible via POST requests and ajax GET requests.');
            } else {
                $this->layout = false;
                $this->loadModel('MispAttribute');
                $attributes = $this->MispAttribute->fetchAttributes($this->Auth->user(), array('conditions' => array('Attribute.id' => $id), 'flatten' => 1));
                if (empty($attributes)) {
                    throw new MethodNotAllowedExeption('Invalid Attribute.');
                }
                $this->set('event_id', $attributes[0]['Attribute']['event_id']);
                $this->set('id', $id);
                $this->render('ajax/add_sighting');
            }
        }
    }

    public function view($idOrUUID)
    {
        $sighting = $this->Sighting->find('first', array(
            'conditions' => Validation::uuid($idOrUUID) ? ['Sighting.uuid' => $idOrUUID] : ['Sighting.id' => $idOrUUID],
            'recursive' => -1,
            'fields' => ['id', 'attribute_id'],
        ));
        $sightings = [];
        if (!empty($sighting)) {
            $sightings = $this->Sighting->listSightings($this->Auth->user(), $sighting['Sighting']['attribute_id'], 'attribute');
        }
        if (empty($sightings)) {
            throw new NotFoundException('Invalid sighting.');
        }
        return $this->RestResponse->viewData($sightings[0]);
    }

    public function advanced($id, $context = 'attribute')
    {
        if (empty($id)) {
            throw new MethodNotAllowedException('Invalid ' . $context . '.');
        }
        $input_id = $id;
        $id = $this->Sighting->explodeIdList($id);
        if ($context == 'attribute') {
            $this->loadModel('MispAttribute');
            $attributes = $this->MispAttribute->fetchAttributes($this->Auth->user(), array('conditions' => array('Attribute.id' => $id), 'flatten' => 1));
            if (empty($attributes)) {
                throw new MethodNotAllowedException('Invalid attribute.');
            }
        } else {
            $events = $this->Sighting->Event->fetchEvent($this->Auth->user(), array('eventid' => $id, 'metadata' => true));
            if (empty($events)) {
                throw new MethodNotAllowedException('Invalid event.');
            }
        }
        $this->set('context', $context);
        $this->set('id', $input_id);
        $this->render('/Sightings/ajax/advanced');
    }

    public function quickAdd($id = false, $type = 1, $onvalue = false)
    {
        if (!$this->userRole['perm_modify_org']) {
            throw new MethodNotAllowedException(__('You are not authorised to remove sightings data as you don\'t have permission to modify your organisation\'s data.'));
        }
        if (!$this->request->is('post')) {
            $this->loadModel('MispAttribute');
            $attribute = $this->MispAttribute->fetchAttributes($this->Auth->user(), array('conditions' => array('Attribute.id' => $id, 'Attribute.deleted' => 0), 'flatten' => 1));
            if (empty($attribute)) {
                throw new MethodNotAllowedException(__('Attribute not found'));
            } else {
                $attribute = $attribute[0]['Attribute'];
                if (!$onvalue) {
                    $this->set('id', $attribute['id']);
                    $this->set('tosight', $attribute['id']);
                } else {
                    $this->set('id', '');
                    $this->set('tosight', $attribute['value']);
                }
                $this->set('value', $attribute['value']);
                $this->set('event_id', $attribute['event_id']);
                $this->set('sighting_type', $type);
                $this->set('onvalue', $onvalue);
                $this->render('ajax/quickAddConfirmationForm');
            }
        } else {
            if (!isset($id)) {
                return new CakeResponse(array('body' => json_encode(array('saved' => true, 'errors' => __('Invalid request.'))), 'status' => 200, 'type' => 'json'));
            } else {
                if ($onvalue) {
                    $result = $this->Sighting->add();
                } else {
                    $result = $this->Sighting->add($id);
                }

                if ($result) {
                    return new CakeResponse(array('body' => json_encode(array('saved' => true, 'success' => __('Sighting added.'))), 'status' => 200, 'type' => 'json'));
                } else {
                    return new CakeResponse(array('body' => json_encode(array('saved' => true, 'errors' => __('Sighting could not be added'))), 'status' => 200, 'type' => 'json'));
                }
            }
        }
    }

    public function quickDelete($id, $rawId, $context)
    {
        if (!$this->request->is('post')) {
            $this->set('id', $id);
            $this->set('rawId', $rawId);
            $this->set('context', $context);
            $this->render('ajax/quickDeleteConfirmationForm');
        } else {
            if (!isset($id)) {
                return new CakeResponse(array('body' => json_encode(array('saved' => true, 'errors' => 'Invalid request.')), 'status' => 200, 'type' => 'json'));
            } else {
                $sighting = $this->Sighting->find('first', array('conditions' => array('Sighting.id' => $id), 'recursive' => -1));
                if (empty($sighting)) {
                    return new CakeResponse(array('body' => json_encode(array('saved' => true, 'errors' => 'Invalid sighting.')), 'status' => 200, 'type' => 'json'));
                }
                if (!$this->ACL->canDeleteSighting($this->Auth->user(), $sighting)) {
                    return new CakeResponse(array('body' => json_encode(array('saved' => true, 'errors' => 'Invalid sighting.')), 'status' => 200, 'type' => 'json'));
                }
                $result = $this->Sighting->delete($id);
                if ($result) {
                    return new CakeResponse(array('body' => json_encode(array('saved' => true, 'success' => 'Sighting deleted.')), 'status' => 200, 'type' => 'json'));
                } else {
                    return new CakeResponse(array('body' => json_encode(array('saved' => true, 'errors' => 'Sighting could not be deleted')), 'status' => 200, 'type' => 'json'));
                }
            }
        }
    }

    // takes a sighting ID or UUID
    public function delete($id)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('This action can only be accessed via a post request.');
        }
        $sighting = $this->Sighting->find('first', array(
            'conditions' => Validation::uuid($id) ? ['Sighting.uuid' => $id] : ['Sighting.id' => $id],
            'recursive' => -1,
            'fields' => ['id', 'org_id'],
        ));
        if (empty($sighting)) {
            throw new NotFoundException('Invalid sighting.');
        }
        if (!$this->ACL->canDeleteSighting($this->Auth->user(), $sighting)) {
            throw new NotFoundException('Invalid sighting.');
        }
        $result = $this->Sighting->delete($sighting['Sighting']['id']);
        if (!$result) {
            return $this->RestResponse->saveFailResponse('Sighting', 'delete', $id, 'Could not delete the Sighting.');
        } else {
            return $this->RestResponse->saveSuccessResponse('Sighting', 'delete', $id, false, 'Sighting successfully deleted.');
        }
    }

    public function index($eventid = false)
    {
        $sightingConditions = $eventid ? array('Sighting.event_id' => $eventid) : [];
        $sightedEvents = $this->Sighting->find('column', array(
            'fields' => array('Sighting.event_id'),
            'conditions' => $sightingConditions,
            'unique' => true,
        ));
        if (empty($sightedEvents)) {
            $this->RestResponse->viewData(array());
        }
        $events = $this->Sighting->Event->fetchEventIds($this->Auth->user(), [
            'eventIdList' => $sightedEvents
        ]);
        $sightings = array();
        if (!empty($events)) {
            foreach ($events as $k => $event) {
                $sightings = array_merge($sightings, $this->Sighting->attachToEvent($event, $this->Auth->user()));
            }
        }
        return $this->RestResponse->viewData($sightings);
    }

    public function listSightings($id = false, $context = 'attribute', $org_id = false)
    {
        $rawId = $id;
        $parameters = array('id', 'context', 'org_id');
        foreach ($parameters as $parameter) {
            if ($this->request->is('post') && isset($this->request->data[$parameter])) {
                ${$parameter} = $this->request->data[$parameter];
            }
        }
        if ($org_id) {
            $this->loadModel('Organisation');
            $org_id = $this->Toolbox->findIdByUuid($this->Organisation, $org_id);
        }
        $sightings = $this->Sighting->listSightings($this->Auth->user(), $id, $context, $org_id);
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($sightings, $this->response->type());
        }

        $this->set('org_id', $org_id);
        $this->set('rawId', $rawId);
        $this->set('context', $context);
        $this->set('types', array('Sighting', 'False-positive', 'Expiration'));
        $this->set('sightings', $sightings);
        $this->layout = false;
        $this->render('ajax/list_sightings');
    }

    public function viewSightings($id, $context = 'attribute')
    {
        $id = $this->Sighting->explodeIdList($id);
        if ($context === 'attribute') {
            $objects = $this->Sighting->Event->Attribute->fetchAttributes($this->Auth->user(), array('conditions' => array('Attribute.id' => $id, 'Attribute.deleted' => 0), 'flatten' => 1));
            if (empty($objects)) {
                throw new MethodNotAllowedException('Invalid object.');
            }
            $statistics = $this->Sighting->attributesStatistics($objects, $this->Auth->user(), true);
        } elseif ($context === 'event') {
            // let's set the context to event here, since we reuse the variable later on for some additional lookups.
            // Passing $context = 'org' could have interesting results otherwise...
            $events = $this->Sighting->Event->fetchSimpleEvents($this->Auth->user(), ['conditions' => ['id' => $id]]);
            $statistics = $this->Sighting->eventsStatistic($events, $this->Auth->user(), true);
        } else {
            throw new MethodNotAllowedException('Invalid context');
        }

        $this->set('csv', $statistics['csv']['all']);
        $this->layout = false;
        $this->render('ajax/view_sightings');
    }

    // Save sightings synced over, restricted to sync users
    public function bulkSaveSightings($eventId = false)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('This method is only accessible via POST requests.');
        }
        if (empty($this->request->data['Sighting'])) {
            $sightings = $this->request->data;
        } else {
            $sightings = $this->request->data['Sighting'];
        }
        try {
            $saved = $this->Sighting->bulkSaveSightings($eventId, $sightings, $this->Auth->user());
            if ($saved > 0) {
                return new CakeResponse(array('body' => json_encode(array('saved' => true, 'success' => $saved . ' sightings added.')), 'status' => 200, 'type' => 'json'));
            } else {
                return new CakeResponse(array('body' => json_encode(array('saved' => false, 'success' => 'No sightings added.')), 'status' => 200, 'type' => 'json'));
            }
        } catch (NotFoundException $e) {
            throw new MethodNotAllowedException($e->getMessage());
        }
    }

    public function filterSightingUuidsForPush($eventId)
    {
        if (!$this->request->is('post')) {
            throw new MethodNotAllowedException('This method is only accessible via POST requests.');
        }

        $event = $this->Sighting->Event->fetchSimpleEvent($this->Auth->user(), $eventId);
        if (empty($event)) {
            throw new NotFoundException("Event not found");
        }

        $incomingSightingUuids = $this->request->data;
        $existingSightingUuids = $this->Sighting->find('column', [
            'fields' => ['Sighting.uuid'],
            'conditions' => [
                'Sighting.uuid' => $incomingSightingUuids,
                'Sighting.event_id' => $event['Event']['id']
            ],
        ]);
        return $this->RestResponse->viewData($existingSightingUuids, $this->response->type());
    }
}
