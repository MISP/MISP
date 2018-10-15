<?php
App::uses('AppController', 'Controller');

class EventGraphController extends AppController
{
    public $components = array(
            'Security',
            'RequestHandler'
    );

    public function beforeFilter()
    {
        parent::beforeFilter();
    }

    public function view($event_id = false)
    {
        if ($event_id === false) {
            throw new MethodNotAllowedException(__('No event ID set.'));
        }

        // retreive current org_id
        $org_id = $this->_checkOrg();

        // validate event
        $this->loadModel('Event');
        if (Validation::uuid($event_id)) {
            $temp = $this->Event->find('first', array('recursive' => -1, 'fields' => array('Event.id'), 'conditions' => array('Event.uuid' => $eventId)));
            if (empty($temp)) {
                throw new NotFoundException('Invalid event');
            }
            $event_id = $temp['Event']['id'];
        } elseif (!is_numeric($event_id)) {
            throw new NotFoundException(__('Invalid event'));
        }

        $event = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $event_id));
        if (empty($event)) {
            throw new NotFoundException('Invalid event');
        }

        // fetch eventGraphs
        $eventGraphs = $this->EventGraph->find('all', array(
            'order' => 'EventGraph.timestamp DESC',
            'conditions' => array(
                'EventGraph.event_id' => $event_id,
                'EventGraph.org_id' => $org_id
            ),
            'contain' => array(
                'User' => array(
                    'fields' => array(
                        'User.email'
                    )
                )
            )
        ));
        return $this->RestResponse->viewData($eventGraphs, $this->response->type());
    }

    public function add($event_id = false)
    {
        if ($this->request->is('get')) {
            if ($this->_isRest()) {
                return $this->RestResponse->describe('EventGraph', 'add', false, $this->response->type());
            }
            $formURL = 'eventGraph_add_form';

            if (!$this->_isSiteAdmin() && (!$this->userRole['perm_modify'] && !$this->userRole['perm_modify_org'])) {
                throw new NotFoundException(__('Invalid event'));
            }

            $this->set('action', 'add');
            $this->set('event_id', $event_id);
            $this->render('ajax/' . $formURL);
        } else {
            if (empty($event_id)) {
                throw new MethodNotAllowedException(__('No event ID set.'));
            }

            $this->loadModel('Event');
            $event = $this->Event->fetchEvent($this->Auth->user(), array('eventid' => $event_id));
            if (empty($event)) {
                throw new NotFoundException('Invalid event');
            }

            $eventGraph = array();
            if (!$this->_isSiteAdmin() && ($event['Event']['orgc_id'] != $this->Auth->user('org_id') && !$this->userRole['perm_modify'])) {
                throw new UnauthorizedException(__('You do not have permission to do that.'));
            } else {
                $eventGraph['EventGraph']['event_id'] = $event_id;
            }

            if (!isset($this->request->data['EventGraph']['network_json'])) {
                throw new MethodNotAllowedException('No network data set');
            } else {
                $eventGraph['EventGraph']['network_json'] = $this->request->data['EventGraph']['network_json'];
            }
            if (!isset($this->request->data['EventGraph']['network_name'])) {
                $eventGraph['EventGraph']['network_name'] = null;
            } else {
                $eventGraph['EventGraph']['network_name'] = $this->request->data['EventGraph']['network_name'];
            }

            if (isset($this->request->data['EventGraph']['preview_img'])) {
                $eventGraph['EventGraph']['preview_img'] = $this->request->data['EventGraph']['preview_img'];
            }

            // Network pushed will be the owner of the authentication key
            $eventGraph['EventGraph']['user_id'] = $this->Auth->user('id');
            $eventGraph['EventGraph']['org_id'] = $this->Auth->user('org_id');

            $result = $this->EventGraph->save(
                $eventGraph,
                true,
                array(
                'event_id',
                'network_json',
                'network_name',
                'timestamp',
                'user_id',
                'org_id',
                'preview_img',
                )
            );
            if ($result) {
                return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'eventGraph saved.')), 'status'=>200, 'type' => 'json'));
            } else {
                return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'eventGraph could not be saved.')), 'status'=>200, 'type' => 'json'));
            }
        }
    }

    public function delete($id)
    {
        if (!$this->request->is('post')) {
            $this->set('id', $id);
            $this->render('ajax/eventGraph_delete_form');
        } else {
            $this->set('id', $id);
            $conditions = array('id' => $id);
            if (!$this->_isSiteAdmin()) {
                $conditions['org_id'] = $this->Auth->user('org_id');
            }
            $eventGraph = $this->EventGraph->find('first', array(
                    'conditions' => $conditions,
                    'recursive' => -1,
                    'fields' => array('id', 'event_id', 'user_id'),
            ));
            if (empty($eventGraph)) {
                throw new NotFoundException('Invalid EventGraph');
            }
            if ($this->request->is('post')) {
                // only creator (or siteAdmin) can delete the eventGraph
                if (($eventGraph['EventGraph']['user_id'] != $this->Auth->user()['id']) && !$this->_isSiteAdmin()) {
                    throw new MethodNotAllowedException('This eventGraph does not belong to you.');
                }
                $result = $this->EventGraph->delete($id);
                if ($result) {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => true, 'success' => 'EventGraph deleted.')), 'status'=>200, 'type' => 'json'));
                } else {
                    return new CakeResponse(array('body'=> json_encode(array('saved' => false, 'errors' => 'EventGraph not deleted.')), 'status'=>200, 'type' => 'json'));
                }
            }
        }
    }
}
