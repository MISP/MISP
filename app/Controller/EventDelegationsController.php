<?php
App::uses('AppController', 'Controller');

class EventDelegationsController extends AppController
{
    public $components = array('Session', 'RequestHandler');

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
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
        $event = $this->EventDelegation->Event->find('first', array(
                'conditions' => array('Event.id' => $id),
                'recursive' => -1,
                'fields' => array('Event.id', 'Event.orgc_id', 'Event.distribution')
        ));
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
        if ($this->request->is('Post')) {
            if ($this->request->data['EventDelegation']['distribution'] != 4) {
                $this->request->data['EventDelegation']['sharing_group_id'] = '0';
            }
            $this->request->data['EventDelegation']['event_id'] = $event['Event']['id'];
            $this->request->data['EventDelegation']['requester_org_id'] = $this->Auth->user('org_id');
            $this->EventDelegation->create();
            $this->EventDelegation->save($this->request->data['EventDelegation']);
            $org = $this->EventDelegation->Event->Org->find('first', array(
                    'conditions' => array('id' => $this->request->data['EventDelegation']['org_id']),
                    'recursive' => -1,
                    'fields' => array('name')
            ));
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
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
            $this->Flash->success('Delegation request created.');
            $this->redirect('/events/view/' . $id);
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
            $sgs = $this->EventDelegation->Event->SharingGroup->fetchAllAuthorised($this->Auth->User, 'name', true);
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
                $this->Flash->success('Event ownership transferred.');
                $this->redirect(array('controller' => 'events', 'action' => 'view', $result));
            } else {
                $this->Flash->error('Something went wrong and the event could not be transferred.');
                $this->redirect(array('controller' => 'Event', 'action' => 'view', $delegation['EventDelegation']['event_id']));
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
            $this->Flash->success('Delegation request deleted.');
            $this->redirect(array('controller' => 'events', 'action' => 'index'));
        } else {
            $this->set('delegationRequest', $delegation);
            $this->render('ajax/delete_delegation');
        }
    }
}
