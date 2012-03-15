<?php
App::uses('AppController', 'Controller');
/**
 * Signatures Controller
 *
 * @property Signature $Signature
 */
class SignaturesController extends AppController {

    public $components = array('Security');
    
    function beforeFilter() {
        // These variables are required for every view
        $this->set('me', $this->Auth->user());
        $this->set('isAdmin', $this->_isAdmin());
    }
    

/**
 * index method
 *
 * @return void
 */
	public function index() {
		$this->Signature->recursive = 0;
		$this->set('signatures', $this->paginate());
	}

/**
 * add method
 *
 * @return void
 */
	public function add($event_id = null) {
		if ($this->request->is('post')) {
		    $this->loadModel('Event');
		    // only own signatures
		    $this->Event->recursive = 0;
		    $event = $this->Event->findById($this->request->data['Signature']['event_id']);
		    if (!$this->_isAdmin() && $this->Auth->user('org') != $event['Event']['org']) {
		        throw new UnauthorizedException('You can only add signatures for your own organisation.');
		    }

		    // remove the alerted flag from the event
		    $this->Event->id = $this->request->data['Signature']['event_id'];
		    $this->Event->saveField('alerted', 0);
		    
		    //
		    // multiple signatures in batch import
		    //
		    if ($this->data['Signature']['batch_import'] == 1) {
		        // make array from value field
		        $signatures = explode("\n", $this->request->data['Signature']['value']);
		        
		        $fails = "";     // will be used to keep a list of the lines that failed or succeeded
		        $successes = "";
		        foreach ($signatures as $key => $signature) {
		            $signature = trim($signature);
		            if (strlen($signature) == 0 )
		            continue; // don't do anything for empty lines
		        
		            $this->Signature->create();
		            $this->request->data['Signature']['value'] = $signature;  // set the value as the content of the single line
		        
		            if ($this->Signature->save($this->request->data)) {
		                $successes .= " ".($key+1);
		            } else {
		                $fails .= " ".($key+1);
		            }
		        
		        }
		        // we added all the signatures,
		        if ($fails) {
		            // list the ones that failed
		            $this->Session->setFlash(__('The lines'.$fails.' could not be saved. Please, try again.', true), 'default', array(), 'error');
		        }
		        if ($successes) {
		            // list the ones that succeeded
		            $this->Session->setFlash(__('The lines'.$successes.' have been saved', true));
		        }
		        
		        $this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Signature']['event_id']));
		        
		    }
		    
		    else {
	        //
            // single signature
            //
		        // create the signature
		    	$this->Signature->create();
    			if ($this->Signature->save($this->request->data)) {
    			    // inform the user and redirect
    				$this->Session->setFlash(__('The signature has been saved'));
    				$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Signature']['event_id']));
    			} else {
    				$this->Session->setFlash(__('The signature could not be saved. Please, try again.'));
    			}
		    }
		} else {
		    // set the event_id in the form
		    $this->request->data['Signature']['event_id'] = $event_id;
		}
		
		// combobox for types
		$types = $this->Signature->validate['type']['rule'][1];
		$types = $this->_arrayToValuesIndexArray($types);
		$this->set('types',compact('types'));
	}

/**
 * edit method
 *
 * @param string $id
 * @return void
 */
	public function edit($id = null) {
		$this->Signature->id = $id;
		if (!$this->Signature->exists()) {
			throw new NotFoundException(__('Invalid signature'));
		}
		// only own signatures
		$this->Signature->read();
		if (!$this->_isAdmin() && $this->Auth->user('org') != $this->Signature->data['Event']['org']) {
		    throw new UnauthorizedException('You can only edit signatures from your own organisation.');
		}
		if ($this->request->is('post') || $this->request->is('put')) {
		    
			if ($this->Signature->save($this->request->data)) {
				$this->Session->setFlash(__('The signature has been saved'));
				$this->redirect(array('action' => 'index'));
			} else {
				$this->Session->setFlash(__('The signature could not be saved. Please, try again.'));
			}
		} else {
			$this->request->data = $this->Signature->read(null, $id);
		}

	}

/**
 * delete method
 *
 * @param string $id
 * @return void
 */
	public function delete($id = null) {
		if (!$this->request->is('post')) {
			throw new MethodNotAllowedException();
		}
		$this->Signature->id = $id;
		if (!$this->Signature->exists()) {
			throw new NotFoundException(__('Invalid signature'));
		}
		
		// only own signatures
		$this->Signature->read();
		if (!$this->_isAdmin() && $this->Auth->user('org') != $this->Signature->data['Event']['org']) {
		    throw new UnauthorizedException('You can only delete signatures from your own organisation.');
		}
		
		if ($this->Signature->delete()) {
			$this->Session->setFlash(__('Signature deleted'));
		} else {
		    $this->Session->setFlash(__('Signature was not deleted'));
		}
		
		$this->redirect($this->referer());
	}
	
	
	
	public function search() {
	    if ($this->request->is('post')) {
	        $keyword = $this->request->data['Signature']['keyword'];
	        
	        // search the db
	        $this->Signature->recursive = 0;
	        $this->paginate = array(
	                'conditions' => array('Signature.value LIKE' => '%'.$keyword.'%'),
	        );
	        $this->set('signatures', $this->paginate());
	
	        // set the same view as the index page
	        $this->render('index');
	    }
	}

}
