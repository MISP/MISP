<?php
App::uses('AppController', 'Controller');

class EventDelegationsController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
            'order' => array(
                'EventDelegations.id' => 'DESC'
            ),
    );

    public function view($id)
    {
        $delegation = $this->EventDelegation->find('first', array(
                'conditions' => array('EventDelegation.id' => $id),
                'recursive' => -1,
                'contain' => array('Org', 'Event', 'RequesterOrg', 'SharingGroup'),
        ));
        if (empty($delegation) || (!$this->_isSiteAdmin() && $this->Auth->user('org_id') != $delegation['EventDelegation']['org_id'] && $this->Auth->user('org_id') != $delegation['EventDelegation']['requester_org_id'])) {
            throw new MethodNotAllowedException('You are not authorised to do that.');
        }
        $delegation['requested_distribution_level'] = $delegation['EventDelegation']['distribution'] == -1 ? false : $this->EventDelegation->Event->distributionLevels[$delegation['EventDelegation']['distribution']];
        $this->set('delegation', $delegation);
        $this->render('ajax/view');
    }

    public function delegateEvent($id)
    {
        $id = $this->Toolbox->findIdByUuid($this->EventDelegation->Event, $id);
        $event = $this->EventDelegation->Event->find('first', array(
                'conditions' => array('Event.id' => $id),
                'recursive' => -1,
                'fields' => array('Event.id', 'Event.orgc_id', 'Event.distribution')
        ));
        if (empty($event)) {
            throw new MethodNotAllowedException('You are not authorised to do that.');
        }
        if (!$this->_isSiteAdmin() && $this->Auth->user('org_id') !== $event['Event']['orgc_id']) {
            throw new MethodNotAllowedException('You are not authorised to do that.');
        }
        if (!Configure::read('MISP.unpublishedprivate') && $event['Event']['distribution'] != 0) {
            throw new MethodNotAllowedException('Only events with the distribution setting "Your Organisation Only" can be delegated.');
        }
        $existingDelegations = $this->EventDelegation->find('first', array('conditions' => array('event_id' => $id), 'recursive' => -1));
        if (!empty($existingDelegations)) {
            throw new MethodNotAllowedException('This event already has a pending delegation request. Please revoke that before creating a new request.');
        }
        if ($this->request->is('post')) {
            if (empty($this->request->data['EventDelegation'])) {
                $this->request->data = array('EventDelegation' => $this->request->data);
            }
            if (empty($this->request->data['EventDelegation']['distribution'])) {
                $this->request->data['EventDelegation']['distribution'] = 0;
            }
            if ($this->request->data['EventDelegation']['distribution'] != 4) {
                $this->request->data['EventDelegation']['sharing_group_id'] = '0';
            }
            $this->request->data['EventDelegation']['event_id'] = $event['Event']['id'];
            $this->request->data['EventDelegation']['requester_org_id'] = $this->Auth->user('org_id');
            $org_id = $this->Toolbox->findIdByUuid($this->EventDelegation->Event->Org, $this->request->data['EventDelegation']['org_id']);
            $this->request->data['EventDelegation']['org_id'] = $org_id;
            $this->EventDelegation->create();
            $result = $this->EventDelegation->save($this->request->data['EventDelegation']);
            $org = $this->EventDelegation->Event->Org->find('first', array(
                    'conditions' => array('id' => $org_id),
                    'recursive' => -1,
                    'fields' => array('name')
            ));
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
            if (empty($result)) {
                $this->Log->save(array(
                        'org' => $this->Auth->user('Organisation')['name'],
                        'model' => 'Event',
                        'model_id' => $event['Event']['id'],
                        'email' => $this->Auth->user('email'),
                        'action' => 'request_delegation',
                        'user_id' => $this->Auth->user('id'),
                        'title' => 'Request of event delegation failed',
                        'change' => 'Request of the delegation of event ' . $event['Event']['id'] . ' to organisation ' . $org['Org']['name'] . ' failed.',
                ));
                throw new InvalidArgumentException('Invalid input, could not create the Delegation Request.');
            }
            $this->Log->save(array(
                    'org' => $this->Auth->user('Organisation')['name'],
                    'model' => 'Event',
                    'model_id' => $event['Event']['id'],
                    'email' => $this->Auth->user('email'),
                    'action' => 'request_delegation',
                    'user_id' => $this->Auth->user('id'),
                    'title' => 'Requested event delegation',
                    'change' => 'Requested the delegation of event ' . $event['Event']['id'] . ' to organisation ' . $org['Org']['name'],
            ));
            if ($this->_isRest()) {
                $delegation_request = $this->EventDelegation->find('first', array(
                    'conditions' => array(
                        'EventDelegation.id' => $this->EventDelegation->id
                    ),
                    'recursive' => -1
                ));
                return $this->RestResponse->viewData($delegation_request, $this->response->type());
            }
            if (!$this->_isRest()) {
                $this->Flash->success('Delegation request created.');
                $this->redirect('/events/view/' . $id);
            } else {
                $delegationRequest = $this->EventDelegation->find("first", array(
                    'recursive' => -1,
                    'conditions' => array('EventDelegation.id' => $this->EventDelegation->id)
                ));
                return $this->RestResponse->viewData($delegationRequest, $this->response->type());
            }
        } else {
            $orgs = $this->EventDelegation->Event->Org->find('list', array(
                    'conditions' => array(
                            'Org.id !=' => $this->Auth->user('org_id'),
                            'Org.local' => 1,
                    ),
                    'fields' => array('name'),
                    'order' => array('lower(name) ASC')
            ));
            $distribution = $this->EventDelegation->Event->distributionLevels;
            $sgs = $this->EventDelegation->Event->SharingGroup->fetchAllAuthorised($this->Auth->user(), 'name', true);
            if (empty($sgs)) {
                unset($distribution[4]);
            }
            $distribution[-1] = 'Recipient decides';
            $this->set('distributionOptions', array('-1' => 'Recipient decides') + $distribution);
            $this->set('org', $orgs);
            $this->set('sgOptions', $sgs);
            $this->set('id', $id);
            $this->render('ajax/delegate_event');
        }
    }

    public function acceptDelegation($id)
    {
        $delegation = $this->EventDelegation->find('first', array(
                'conditions' => array('EventDelegation.id' => $id),
                'recursive' => -1,
                'contain' => array('Org', 'Event', 'RequesterOrg'),
        ));
        if (empty($delegation) || (!$this->_isSiteAdmin() && $this->Auth->user('org_id') != $delegation['EventDelegation']['org_id'])) {
            throw new MethodNotAllowedException('You are not authorised to do that.');
        }
        if ($this->request->is('post')) {
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
            $this->Log->save(array(
                    'org' => $this->Auth->user('Organisation')['name'],
                    'model' => 'Event',
                    'model_id' => $delegation['Event']['id'],
                    'email' => $this->Auth->user('email'),
                    'action' => 'accept_delegation',
                    'user_id' => $this->Auth->user('id'),
                    'title' => 'Accepted event delegation',
                    'change' => 'Starting the transfer of event ' . $delegation['Event']['id'] . ' to organisation ' . $this->Auth->user('Organisation')['name'],
            ));
            $result = $this->EventDelegation->transferEvent($delegation, $this->Auth->user());
            $this->EventDelegation->delete($delegation['EventDelegation']['id']);
            if ($result) {
                $this->Log->create();
                $this->Log->save(array(
                        'org' => $this->Auth->user('Organisation')['name'],
                        'model' => 'Event',
                        'model_id' => 0,
                        'email' => $this->Auth->user('email'),
                        'action' => 'accept_delegation',
                        'user_id' => $this->Auth->user('id'),
                        'title' => 'Completed event delegation',
                        'change' => 'Event ' . $delegation['Event']['id'] . ' successfully transferred to organisation ' . $this->Auth->user('Organisation')['name'],
                ));
                $message = 'Event ownership transferred.';
                if (!$this->_isRest()) {
                    $this->Flash->success($message);
                    $this->redirect(array('controller' => 'events', 'action' => 'view', $result));
                } else {
                    return $this->RestResponse->saveSuccessResponse('EventDelegation', 'acceptDelegation', $id, $this->response->type(), $message);
                }
            } else {
                $message = 'Something went wrong and the event could not be transferred.';
                if (!$this->_isRest()) {
                    $this->Flash->error($message);
                    $this->redirect(array('controller' => 'Event', 'action' => 'view', $delegation['EventDelegation']['event_id']));
                } else {
                    return $this->RestResponse->saveFailResponse('EventDelegation', 'acceptDelegation', $id, $message, $this->response->type());
                }
            }
        } else {
            $this->set('delegationRequest', $delegation);
            $this->render('ajax/accept_delegation');
        }
    }

    public function deleteDelegation($id)
    {
        $delegation = $this->EventDelegation->find('first', array(
            'conditions' => array('EventDelegation.id' => $id),
            'recursive' => -1,
            'contain' => array('Org', 'Event', 'RequesterOrg'),
        ));
        if (empty($delegation) || (!$this->_isSiteAdmin() && !in_array($this->Auth->user('org_id'), array($delegation['EventDelegation']['requester_org_id'], $delegation['EventDelegation']['org_id'])))) {
            throw new MethodNotAllowedException('You are not authorised to do that.');
        }
        if ($this->request->is('post')) {
            $this->EventDelegation->delete($delegation['EventDelegation']['id']);
            $message = 'Delegation request deleted.';
            if (!$this->_isRest()) {
                $this->Flash->success($message);
                $this->redirect(array('controller' => 'events', 'action' => 'index'));
            } else {
                return $this->RestResponse->saveSuccessResponse('EventDelegation', 'deleteDelegation', $id, $this->response->type(), $message);
            }

        } else {
            $this->set('delegationRequest', $delegation);
            $this->render('ajax/delete_delegation');
        }
    }

    public function index()
    {
        $context = 'pending';
        if ($this->request->is('post') && !empty($this->request->data['context'])) {
            $context = $this->request->data['context'];
        } else if (!empty($this->params['named']['context'])) {
            $context = $this->params['named']['context'];
        }
        if ($context === 'pending') {
            $conditions = array('EventDelegation.org_id' => $this->Auth->user('org_id'));
        } else if ($context === 'issued') {
            $conditions = array('EventDelegation.requester_org_id' => $this->Auth->user('org_id'));
        } else {
            throw new InvalidArgumentException('Invalid context. Expected values: pending or issued.');
        }
        if (!empty($this->params['named']['value'])) {
            $temp = array();
            $temp['lower(EventDelegation.message) like'] = '%' . strtolower(trim($this->params['named']['value'])) . '%';
            $temp['lower(Event.info) like'] = '%' . strtolower(trim($this->params['named']['value'])) . '%';
            $temp['lower(Org.name) like'] = '%' . strtolower(trim($this->params['named']['value'])) . '%';
            $temp['lower(RequesterOrg.name) like'] = '%' . strtolower(trim($this->params['named']['value'])) . '%';
            $conditions['AND'][] = array('OR' => $temp);
        }
        $org_fields = array('id', 'name', 'uuid');
        $event_fields = array('id', 'info', 'uuid', 'analysis', 'distribution', 'threat_level_id', 'date', 'attribute_count');
        $params = array(
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => array(
                'Event' => array('fields' => $event_fields),
                'Org' => array('fields' => $org_fields),
                'RequesterOrg' => array('fields' => $org_fields)
            )
        );
        $this->paginate = array_merge($this->paginate, $params);
        $delegation_requests = $this->paginate();
        foreach ($delegation_requests as $k => $v) {
            if ($v['EventDelegation']['distribution'] == -1) {
                unset($delegation_requests[$k]['EventDelegation']['distribution']);
            }
            if ($v['EventDelegation']['sharing_group_id'] == 0) {
                unset($delegation_requests[$k]['EventDelegation']['sharing_group_id']);
            }
            unset($v['EventDelegation']);
            $delegation_requests[$k]['EventDelegation'] = array_merge($delegation_requests[$k]['EventDelegation'], $v);
            $delegation_requests[$k] = array('EventDelegation' => $delegation_requests[$k]['EventDelegation']);
        }
        if ($this->_isRest()) {
            return $this->RestResponse->viewData($delegation_requests, $this->response->type());
        } else {
            $this->set('context', $context);
            $this->set('delegation_requests', $delegation_requests);
            $this->set('passedArgs', json_encode($this->passedArgs, true));
        }
    }
}
