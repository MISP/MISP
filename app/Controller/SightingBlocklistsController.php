<?php
App::uses('AppController', 'Controller');

class SightingBlocklistsController extends AppController
{
    public $components = array('Session', 'RequestHandler', 'BlockList');

    public function beforeFilter()
    {
        parent::beforeFilter();
        if (!$this->_isSiteAdmin()) {
            $this->redirect('/');
        }
        if (Configure::check('MISP.enableSightingBlocklisting') && !Configure::read('MISP.enableSightingBlocklisting') !== false) {
            $this->Flash->info(__('Sighting BlockListing is not currently enabled on this instance.'));
            $this->redirect('/');
        }
    }

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user van view/page.
            'order' => array(
                    'SightingBlocklist.created' => 'DESC'
            ),
    );

    public function index()
    {
        return $this->BlockList->index($this->_isRest());
    }

    public function add()
    {
        return $this->BlockList->add($this->_isRest());
    }

    public function edit($id)
    {
        return $this->BlockList->edit($this->_isRest(), $id);
    }

    public function delete($id)
    {
        return $this->BlockList->delete($this->_isRest(), $id);
    }
}
