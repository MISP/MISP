<?php
App::uses('AppController', 'Controller');

class EventBlacklistsController extends AppController
{
    public $components = array('Session', 'RequestHandler', 'BlackList');

    public function beforeFilter()
    {
        parent::beforeFilter();
        if (!$this->_isSiteAdmin()) {
            $this->redirect('/');
        }
        if (false === Configure::read('MISP.enableEventBlacklisting')) {
            $this->Flash->info(__('Event Blacklisting is not currently enabled on this instance.'));
            $this->redirect('/');
        }
    }

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999,	// LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
            'order' => array(
                    'EventBlacklist.created' => 'DESC'
            ),
    );

    public function index()
    {
		$params = array();
		$validParams = array('event_uuid', 'comment');
		foreach ($validParams as $validParam) {
			if (!empty($this->params['named'][$validParam])) {
				$params[$validParam] = $this->params['named'][$validParam];
			}
		}
        $this->BlackList->index($this->_isRest(), $params);
    }

    public function add()
    {
        $this->BlackList->add($this->_isRest());
    }

    public function edit($id)
    {
        $this->BlackList->edit($this->_isRest(), $id);
    }

    public function delete($id)
    {
        $this->BlackList->delete($this->_isRest(), $id);
    }
}
