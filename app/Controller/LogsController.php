<?php
App::uses('AppController', 'Controller');
/**
 * Logs Controller
 *
 * @property Log $Log
 */
class LogsController extends AppController {

    public $components = array('Security', 'RequestHandler');
//    public $components = array('Security');
    public $paginate = array(
            'limit' => 60,
    		'order' => array(
                    'Log.id' => 'DESC'
            )
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
        // the other pages are allowed by logged in users
        return true;
    }
    
/**
 * admin_index method
 *
 * @return void
 */
	public function admin_index() {
		$this->Log->recursive = 0;
		$this->set('logs', $this->paginate());
	}

/**
 * admin_view method
 *
 * @param string $id
 * @return void
 */
	public function admin_view($id = null) {
		$this->Log->id = $id;
		if (!$this->Log->exists()) {
			throw new NotFoundException(__('Invalid log'));
		}
		$this->set('log', $this->Log->read(null, $id));
	}
	
	public function search() {
		$this->admin_search();
	}
	
	public function admin_search() {

	    $this->set('log_descriptions', $this->Log->field_descriptions);
		
	    if ($this->request->is('post')) {
	        $keyword_email = $this->request->data['Log']['keyword_email'];
	        $keyword_org = $this->request->data['Log']['keyword_org'];
	    	$keyword_action = $this->request->data['Log']['keyword_action'];
	        $keyword_title = $this->request->data['Log']['keyword_title'];
	        $keyword_change = $this->request->data['Log']['keyword_change'];
	        
	        // search the db
	        $conditions = array();
            if($keyword_email) {
                $conditions['Log.email LIKE'] = '%'.$keyword_email.'%';
            }
	        if($keyword_org) {
                $conditions['Log.org LIKE'] = '%'.$keyword_org.'%';
            }
	        if($keyword_action) {
                $conditions['Log.action LIKE'] = '%'.$keyword_action.'%';
            }
	        if($keyword_title) {
                $conditions['Log.title LIKE'] = '%'.$keyword_title.'%';
            }
            if($keyword_change) {
                $conditions['Log.change LIKE'] = '%'.$keyword_change.'%';
            }
            $this->Log->recursive = 0;
            $this->paginate = array(
                'conditions' => $conditions
            );
	        $this->set('logs', $this->paginate());

	        // set the same view as the index page
	        $this->render('index');
	    } else {
	        // no search keyword is given, show the search form
        }
	}
}
