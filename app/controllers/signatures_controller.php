<?php

class SignaturesController extends AppController {

    var $name = 'Signatures';
    var $components = array('Security');

    function beforeFilter() {
        
        // Prevent XSRF
        $this->Security->requireAuth('add', 'edit');
        
        // These variables are required for every view
        $me_user = $this->Auth->user();
        $this->set('me', $me_user['User']);
        $this->set('isAdmin', $this->isAdmin());
    }
    
    function index() {
        $this->Signature->recursive = 0;
        $this->set('signatures', $this->paginate());
    }

    function view($id = null) {
        if (!$id) {
            $this->Session->setFlash(__('Invalid signature', true), 'default', array(), 'error');
            $this->redirect(array('action' => 'index'));
        }
        $this->set('signature', $this->Signature->read(null, $id));
    }

    function add($event_id = null) {
        if (!$event_id && empty($this->data)) {
            $this->Session->setFlash(__('Invalid id for event', true), 'default', array(), 'error');
            $this->redirect(array('controller' => 'events', 'action'=>'index'));
        }
        if ($event_id || !empty($this->data)) {
            // only add signatures from events of yourself
            $user = $this->Auth->user();
            if (!empty($this->data))
                $old_signature = $this->Signature->Event->read(null, $this->data['Signature']['event_id']);
            else
                $old_signature = $this->Signature->Event->read(null, $event_id);
            if (!$this->isAdmin() && $user['User']['org'] != $old_signature['Event']['org']) {
                $this->Session->setFlash(__('You can only add signatures for your own organisation.', true), 'default', array(), 'error');
                $this->redirect(array('controller' => 'events', 'action' => 'view', $old_signature['Event']['id']));
            }
            
        }
        
        if (!empty($this->data)) {
            // create the signature
            $this->Signature->create();
            
            if ($this->Signature->save($this->data)) {
                // remove the alerted flag from the event    
                $this->loadModel('Event');
                $event = $this->Event->read(null, $this->data['Signature']['event_id']);
                $event['Event']['alerted'] = 0;
                $this->Event->save($event);
                // inform the user and redirect
                $this->Session->setFlash(__('The signature has been saved', true));
                $this->redirect(array('controller' => 'events', 'action' => 'view', $this->data['Signature']['event_id']));
            } else {
                $this->Session->setFlash(__('The signature could not be saved. Please, try again.', true), 'default', array(), 'error');
            }
        }
        if (empty($this->data)) {
            $this->data['Signature']['event_id'] = $event_id;
        }
        
        // combobox for types
        $types = $this->Signature->validate['type']['allowedChoice']['rule'][1];
        $types = $this->arrayToValuesIndexArray($types);
        $this->set('types',compact('types'));       
    }

    function edit($id = null) {
        if (!$id && empty($this->data)) {
            $this->Session->setFlash(__('Invalid signature', true), 'default', array(), 'error');
            $this->redirect(array('controller' => 'events', 'action' => 'index'));
        }
        // only edit own signatures (from events of yourself)
        $user = $this->Auth->user();
        $old_signature = $this->Signature->read(null, $id);
        if (!$this->isAdmin() && $user['User']['org'] != $old_signature['Event']['org']) {
            $this->Session->setFlash(__('You can only edit signatures from your own organisation.', true), 'default', array(), 'error');
            $this->redirect(array('controller' => 'events', 'action' => 'view', $old_signature['Event']['id']));
        }
     
        // form submit
        if (!empty($this->data)) {
            // block naughty stuff where the id or event_id are changed in the form
            if ($this->data['Signature']['id'] != $id ||
                $this->data['Signature']['event_id'] != $old_signature['Signature']['event_id']) {
                $this->Session->setFlash(__('You can only edit signatures from your own organisation.', true), 'default', array(), 'error');
                $this->redirect(array('controller' => 'events', 'action' => 'view', $old_signature['Event']['id']));
            }

            // data is valid, let's save the update
            if ($this->Signature->save($this->data)) {
                // remove the alerted flag from the event    
                $this->loadModel('Event');
                $event = $this->Event->read(null, $this->data['Signature']['event_id']);
                $event['Event']['alerted'] = 0;
                $this->Event->save($event);
                // inform the user and redirect
                $this->Session->setFlash(__('The signature has been saved', true));
                $this->redirect(array('controller' => 'events', 'action' => 'view', $this->data['Signature']['event_id']));
            } else {
                $this->Session->setFlash(__('The signature could not be saved. Please, try again.', true), 'default', array(), 'error');
            }
        }
        if (empty($this->data)) {
            $this->data = $this->Signature->read(null, $id);
        }

        $events = $this->Signature->Event->find('list');
        $this->set(compact('events'));
        
        // combobox for types
        $types = $this->Signature->validate['type']['allowedChoice']['rule'][1];
        $types = $this->arrayToValuesIndexArray($types);
        $this->set('types',compact('types'));
    }

    function delete($id = null) {
        if (!$id) {
            $this->Session->setFlash(__('Invalid id for signature', true), 'default', array(), 'error');
            $this->redirect(array('action'=>'index'));
        }
        // only delete own signatures (from events of yourself)
        $user = $this->Auth->user();
        $old_signature = $this->Signature->read(null, $id);
        if (!$this->isAdmin() && $user['User']['org'] != $old_signature['Event']['org']) {
            $this->Session->setFlash(__('You can only delete signatures from your own organisation.', true), 'default', array(), 'error');
            $this->redirect(array('controller' => 'events', 'action' => 'view', $old_signature['Event']['id']));
        }
        // delete the signature
        if ($this->Signature->delete($id)) {
            $this->Session->setFlash(__('Signature deleted', true));
            $this->redirect(array('controller' => 'events', 'action' => 'view', $old_signature['Event']['id']));
        }
        $this->Session->setFlash(__('Signature was not deleted', true), 'default', array(), 'error');
        $this->redirect(array('action' => 'index'));
    }
    
    
    function search($keyword = null) {
        if (!$keyword && !isset($this->data['Signature']['keyword'])) {
            // no search keyword is given, show the search form
        } else {
            if (!$keyword) $keyword = $this->data['Signature']['keyword'];
            
            // search the db   
            $this->Signature->recursive = 0;
            $this->paginate = array(
                'conditions' => array('Signature.value LIKE' => '%'.$keyword.'%'),
            );
            $this->set('signatures', $this->paginate());
            
            // set the same view as the index page
            $this->action = 'index';    
            
        }        
    }
}
