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

	    $this->set('actionDefinitions', $this->Log->actionDefinitions);

	    if ($this->request->is('post')) {
	        $email = $this->request->data['Log']['email'];
	        $org = $this->request->data['Log']['org'];
	    	$action = $this->request->data['Log']['action'];
	        $title = $this->request->data['Log']['title'];
	        $change = $this->request->data['Log']['change'];

	        // search the db
	        $conditions = array();
            if($email) {
                $conditions['Log.email LIKE'] = '%'.$email.'%';
            }
	        if($org) {
                $conditions['Log.org LIKE'] = '%'.$org.'%';
            }
            if($action != 'ALL') {
                $conditions['Log.action ='] = $action;
            }
	        if($title) {
                $conditions['Log.title LIKE'] = '%'.$title.'%';
            }
            if($change) {
                $conditions['Log.change LIKE'] = '%'.$change.'%';
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

	        // combobox for actions
    	    $actions = array('' => array('ALL' => 'ALL'), 'actions' => array());
    	    $actions['actions'] = array_merge($actions['actions'], $this->_arrayToValuesIndexArray($this->Log->validate['action']['rule'][1]));
    	    $this->set('actions',$actions);
	    }
	}
}
