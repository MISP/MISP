<?php
App::uses('AppController', 'Controller');
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');

/**
 * Attributes Controller
 *
 * @property Attribute $Attribute
 */
class AttributesController extends AppController {

    public $components = array('Security', 'RequestHandler');
    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999,  // LATER we will bump here on a problem once we have more than 9999 events
    );
    public $helpers = array('Js' => array('Jquery'));

    function beforeFilter() {
        parent::beforeFilter();

        // permit reuse of CSRF tokens on the search page.
        if ('search' == $this->request->params['action']) {
            $this->Security->csrfUseOnce = false;
        }
    }


    public function isAuthorized($user) {
        // Admins can access everything
        if (parent::isAuthorized($user)) {
            return true;
        }
        // Only on own attributes for these actions
        if (in_array($this->action, array('edit', 'delete'))) {
            $attributeid = $this->request->params['pass'][0];
            return $this->Attribute->isOwnedByOrg($attributeid, $this->Auth->user('org'));
        }
        // Only on own events for these actions
        if (in_array($this->action, array('add', 'add_attachment'))) {
            $this->loadModel('Event');
            $eventid = $this->request->params['pass'][0];
            return $this->Event->isOwnedByOrg($eventid, $this->Auth->user('org'));
        }
        // the other pages are allowed by logged in users
        return true;
    }

/**
 * index method
 *
 * @return void
 */
	public function index() {
		$this->Attribute->recursive = 0;
		$this->set('attr_descriptions', $this->Attribute->field_descriptions);
		$this->set('attributes', $this->paginate());
		
		$this->set('attr_descriptions', $this->Attribute->field_descriptions);
		$this->set('type_definitions', $this->Attribute->type_definitions);
		$this->set('category_definitions', $this->Attribute->category_definitions);
		
	}

/**
 * add method
 *
 * @return void
 */
	public function add($event_id = null) {
		if ($this->request->is('post')) {
		    $this->loadModel('Event');
		    // only own attributes verified by isAuthorized

            // Give error if someone tried to submit a attribute with attachment or malware-sample type.
		    // FIXME this is bad ... it should rather by a messagebox or should be filtered out on the view level
		    if($this->Attribute->typeIsAttachment($this->request->data['Attribute']['type'])) {
		        $this->Session->setFlash(__('Attribute has not been added: attachments are added by "Add attachment" button', true), 'default', array(), 'error');
		        $this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));
		    }


		    // remove the published flag from the event
		    $this->Event->id = $this->request->data['Attribute']['event_id'];
		    $this->Event->saveField('published', 0);

		    //
		    // multiple attributes in batch import
		    //
		    if ($this->request->data['Attribute']['batch_import'] == 1) {
		        // make array from value field
		        $attributes = explode("\n", $this->request->data['Attribute']['value']);

		        $fails = "";     // will be used to keep a list of the lines that failed or succeeded
		        $successes = "";
		        foreach ($attributes as $key => $attribute) {
		            $attribute = trim($attribute);
		            if (strlen($attribute) == 0 )
		            continue; // don't do anything for empty lines

		            $this->Attribute->create();
		            $this->request->data['Attribute']['value'] = $attribute;  // set the value as the content of the single line
		            if ($this->Attribute->save($this->request->data)) {
		                $successes .= " ".($key+1);
		            } else {
		                $fails .= " ".($key+1);
		            }

		        }
		        // we added all the attributes,
		        if ($fails) {
		            // list the ones that failed
		            $this->Session->setFlash(__('The lines'.$fails.' could not be saved. Please, try again.', true), 'default', array(), 'error');
		        }
		        if ($successes) {
		            // list the ones that succeeded
		            $this->Session->setFlash(__('The lines'.$successes.' have been saved', true));
		        }

		        $this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));

		    }

		    else {
	        //
            // single attribute
            //
		        // create the attribute
		    	$this->Attribute->create();

    			if ($this->Attribute->save($this->request->data)) {
    			    // inform the user and redirect
    				$this->Session->setFlash(__('The attribute has been saved'));
    				$this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));
    			} else {
    				$this->Session->setFlash(__('The attribute could not be saved. Please, try again.'));
    			}
		    }
		} else {
		    // set the event_id in the form
		    $this->request->data['Attribute']['event_id'] = $event_id;
		}

		// combobox for types
		$types = $this->Attribute->validate['type']['rule'][1];
		$types = $this->_arrayToValuesIndexArray($types);
		$this->set('types',compact('types'));
		// combobos for categories
		$categories = $this->Attribute->validate['category']['rule'][1];
		$categories = $this->_arrayToValuesIndexArray($categories);
		$this->set('categories',compact('categories'));
		
		$this->set('attr_descriptions', $this->Attribute->field_descriptions);
		$this->set('type_definitions', $this->Attribute->type_definitions);
		$this->set('category_definitions', $this->Attribute->category_definitions);
	}


	public function download($id = null) {
	    $this->Attribute->id = $id;
	    if (!$this->Attribute->exists()) {
	        throw new NotFoundException(__('Invalid attribute'));
	    }

	    $this->Attribute->read();
	    $file = new File(APP.DS."files".DS.$this->Attribute->data['Attribute']['event_id'].DS.$this->Attribute->data['Attribute']['id']);
	    $filename = '';
        if('attachment' == $this->Attribute->data['Attribute']['type']) {
            $filename= $this->Attribute->data['Attribute']['value'];
        } elseif ('malware-sample'== $this->Attribute->data['Attribute']['type']) {
            $filename_hash = explode('|', $this->Attribute->data['Attribute']['value']);
            $filename = $filename_hash[0].".zip";
        } else {
            throw new NotFoundException(__('Attribute not an attachment or malware-sample'));
        }

        $file_ext = explode(".", $filename);
        $this->viewClass = 'Media';
        $params = array(
                'id'        => $file->path,
                'name'      => $filename,
                'download'  => true,
                'path'      => DS
        );
        $this->set($params);
	}

/**
 * add_attachment method
 *
 * @return void
 */
	public function add_attachment($event_id = null) {
	    if ($this->request->is('post')) {
	        $this->loadModel('Event');
		    // only own attributes verified by isAuthorized

	        // Check if there were problems with the file upload
	        // only keep the last part of the filename, this should prevent directory attacks
	        $filename = basename($this->request->data['Attribute']['value']['name']);
	        $tmpfile = new File($this->request->data['Attribute']['value']['tmp_name']);
	        if ((isset($this->request->data['Attribute']['value']['error']) && $this->request->data['Attribute']['value']['error'] == 0) ||
	                (!empty( $this->request->data['Attribute']['value']['tmp_name']) && $this->request->data['Attribute']['value']['tmp_name'] != 'none')
	        ) {
	            if(!is_uploaded_file($tmpfile->path))
	                throw new InternalErrorException('PHP says file was not uploaded. Are you attacking me?');
	        } else {
	            $this->Session->setFlash(__('There was a problem to upload the file.', true), 'default', array(), 'error');
	            $this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));
	        }

	        // remove the published flag from the event
	        $this->Event->id = $this->request->data['Attribute']['event_id'];
	        $this->Event->saveField('published', 0);

	        // save the file-info in the database
	        $this->Attribute->create();
	        if($this->request->data['Attribute']['malware']) {
	            $this->request->data['Attribute']['type'] = "malware-sample";
	            $this->request->data['Attribute']['value'] = $filename.'|'.$tmpfile->md5(); // TODO gives problems with bigger files
	        }
	        else {
	            $this->request->data['Attribute']['type'] = "attachment";
	            $this->request->data['Attribute']['value'] = $filename;
	        }
	        $this->request->data['Attribute']['uuid'] = String::uuid();
	        $this->request->data['Attribute']['to_ids'] = 0; // LATER permit user to send this to IDS
	        $this->request->data['Attribute']['batch_import'] = 0;

	        if ($this->Attribute->save($this->request->data)) {
	             // attribute saved correctly in the db
	        } else {
	            $this->Session->setFlash(__('The attribute could not be saved. Did you already upload this file?'));
	            $this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));
	        }

	        // no errors in file upload, entry already in db, now move the file where needed and zip it if required.
	        // no sanitization is required on the filename, path or type as we save
	        // create directory structure
	        $root_dir = APP.DS."files".DS.$this->request->data['Attribute']['event_id'];
	        $dir = new Folder($root_dir, true);
	        // move the file to the correct location
	        $destpath = $root_dir.DS.$this->Attribute->id;   // id of the new attribute in the database
	        $file = new File ($destpath);
	        $zipfile = new File ($destpath.'.zip');
	        $file_in_zip = new File($root_dir.DS.$filename); // FIXME do sanitization of the filename

	        if($file->exists() || $zipfile->exists() || $file_in_zip->exists()) {
	            // this should never happen as the attribute id should be unique
	            $this->Session->setFlash(__('Attachment with this name already exist in this event.', true), 'default', array(), 'error');
	            // remove the entry from the database
	            $this->Attribute->delete();
	            $this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));
	        }
	        if(!move_uploaded_file($tmpfile->path, $file->path)) {
	            $this->Session->setFlash(__('Problem with uploading attachment. Cannot move it to its final location.', true), 'default', array(), 'error');
	            // remove the entry from the database
	            $this->Attribute->delete();
	            $this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));
	        }

	        // zip and password protect the malware files
	        if($this->request->data['Attribute']['malware']) {
	            // TODO check if CakePHP has no easy/safe wrapper to execute commands
	            $exec_retval = ''; $exec_output = array();
	            rename($file->path, $file_in_zip->path); // TODO check if no workaround exists for the current filtering mechanisms
	            exec("zip -j -P infected ".$zipfile->path.' "'.addslashes($file_in_zip->path).'"', $exec_output, $exec_retval);
	            if($exec_retval != 0) {   // not EXIT_SUCCESS
	                $this->Session->setFlash(__('Problem with zipping the attachment. Please report to administrator. '.$exec_output, true), 'default', array(), 'error');
	                // remove the entry from the database
	                $this->Attribute->delete();
	                $file_in_zip->delete();
	                $file->delete();
	                $this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));
	            };
	            $file_in_zip->delete();              // delete the original not-zipped-file
	            rename($zipfile->path, $file->path); // rename the .zip to .nothing
	        }

	        // everything is done, now redirect to event view
	        $this->Session->setFlash(__('The attachment has been uploaded'));
	        $this->redirect(array('controller' => 'events', 'action' => 'view', $this->request->data['Attribute']['event_id']));

	    } else {
	        // set the event_id in the form
	        $this->request->data['Attribute']['event_id'] = $event_id;
	    }

	    // combobos for categories
	    $categories = $this->Attribute->validate['category']['rule'][1];
	    $categories = $this->_arrayToValuesIndexArray($categories);
	    $this->set('categories',compact('categories'));
	    
	    $this->set('attr_descriptions', $this->Attribute->field_descriptions);
	    $this->set('type_definitions', $this->Attribute->type_definitions);
	    $this->set('category_definitions', $this->Attribute->category_definitions);
	    
	}

/**
 * edit method
 *
 * @param string $id
 * @return void
 */
	public function edit($id = null) {
		$this->Attribute->id = $id;
		if (!$this->Attribute->exists()) {
			throw new NotFoundException(__('Invalid attribute'));
		}
		// only own attributes verified by isAuthorized

		$this->Attribute->read();
		$event_id = $this->Attribute->data['Attribute']['event_id'];
        if('attachment' == $this->Attribute->data['Attribute']['type'] ||
           'malware-sample'== $this->Attribute->data['Attribute']['type'] ) {
            $this->set('attachment', true);
            //    FIXME we should ensure value cannot be changed here and not only on a view level (because of the associated file)
            //    $this->Session->setFlash(__('You cannot edit attachment attributes.', true), 'default', array(), 'error');
            //    $this->redirect(array('controller' => 'events', 'action' => 'view', $old_attribute['Event']['id']));
        } else {
            $this->set('attachment', false);
        }

		if ($this->request->is('post') || $this->request->is('put')) {
		    // say what fields are to be updated
		    $fieldList=array('category', 'type', 'value1', 'value2', 'to_ids', 'private');
			if ($this->Attribute->save($this->request->data, true, $fieldList)) {
				$this->Session->setFlash(__('The attribute has been saved'));

				// remove the published flag from the event
				$this->loadModel('Event');
				$this->Event->id = $event_id;
				$this->Event->saveField('published', 0);


				$this->redirect(array('controller' => 'events', 'action' => 'view', $event_id));
			} else {
				$this->Session->setFlash(__('The attribute could not be saved. Please, try again.'));
			}
		} else {
			$this->request->data = $this->Attribute->read(null, $id);
		}

		// combobox for types
		$types = $this->Attribute->validate['type']['rule'][1];
		$types = $this->_arrayToValuesIndexArray($types);
		$this->set('types',compact('types'));
		// combobox for categories
		$categories = $this->Attribute->validate['category']['rule'][1];
		$categories = $this->_arrayToValuesIndexArray($categories);
		$this->set('categories',compact('categories'));

		$this->set('attr_descriptions', $this->Attribute->field_descriptions);
		$this->set('type_definitions', $this->Attribute->type_definitions);
		$this->set('category_definitions', $this->Attribute->category_definitions);
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
		$this->Attribute->id = $id;
		if (!$this->Attribute->exists()) {
			throw new NotFoundException(__('Invalid attribute'));
		}
		// only own attributes verified by isAuthorized

		// attachment will be deleted with the beforeDelete() function in the Model
		if ($this->Attribute->delete()) {
			$this->Session->setFlash(__('Attribute deleted'));
		} else {
		    $this->Session->setFlash(__('Attribute was not deleted'));
		}

		$this->redirect($this->referer());
	}



	public function search() {
	    if ($this->request->is('post')) {
	        $keyword = $this->request->data['Attribute']['keyword'];
	        $type = $this->request->data['Attribute']['type'];
	        $category = $this->request->data['Attribute']['category'];

	        // search the db
	        $conditions = array();
            if($keyword) {
                $conditions['Attribute.value LIKE'] = '%'.$keyword.'%';
            }
            if($type != 'ALL') {
                $conditions['Attribute.type ='] = $type;
            }
            if($category != 'ALL') {
                $conditions['Attribute.category ='] = $category;
            }
            $this->Attribute->recursive = 0;
            $this->paginate = array(
                'conditions' => $conditions
            );
	        $this->set('attributes', $this->paginate());

	        // set the same view as the index page
	        $this->render('index');
	    } else {
	        // no search keyword is given, show the search form

	        // adding filtering by category and type
    	    // combobox for types
    	    $types = array('ALL');
    	    $types = array_merge($types, $this->Attribute->validate['type']['rule'][1]);
    	    $types = $this->_arrayToValuesIndexArray($types);
    	    $this->set('types',compact('types'));

    	    // combobox for categories
    	    $categories = array('ALL');
    	    $categories = array_merge($categories, $this->Attribute->validate['category']['rule'][1]);
    	    $categories = $this->_arrayToValuesIndexArray($categories);
    	    $this->set('categories',compact('categories'));
    	    
    	    $this->set('type_definitions', $this->Attribute->type_definitions);
    	    $this->set('category_definitions', $this->Attribute->category_definitions);
	    }

	}

}
