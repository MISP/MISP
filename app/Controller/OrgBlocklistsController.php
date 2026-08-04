<?php
App::uses('AppController', 'Controller');

class OrgBlocklistsController extends AppController
{
    public $components = array('Session', 'RequestHandler', 'BlockList');

    public function beforeFilter()
    {
        parent::beforeFilter();
        if (!$this->_isSiteAdmin()) {
            $this->redirect('/');
        }
        if (Configure::check('MISP.enableOrgBlocklisting') && !Configure::read('MISP.enableOrgBlocklisting') !== false) {
            $this->Flash->info(__('Organisation BlockListing is not currently enabled on this instance.'));
            $this->redirect('/');
        }
    }

    public $paginate = array(
            'limit' => 60,
            'maxLimit' => 9999, // LATER we will bump here on a problem once we have more than 9999 events <- no we won't, this is the max a user can view/page.
            'order' => array(
                    'OrgBlocklist.created' => 'DESC'
            ),
    );

    public function index()
    {
        return $this->BlockList->index($this->_isRest());
    }

    public function add()
    {
        $response = $this->BlockList->add($this->_isRest());
        if ($this->_isRest()) {
            return $response;
        }
        if ($this->theme === 'Overmind') {
            $this->layout = false;
            $this->render('add');
        }
    }

    public function edit($id)
    {
        $response = $this->BlockList->edit($this->_isRest(), $id);
        if ($this->_isRest()) {
            return $response;
        }
        if ($this->theme === 'Overmind') {
            $this->layout = false;
            $this->render('add');
        }
    }

    public function delete($id)
    {
        return $this->BlockList->delete($this->_isRest(), $id);
    }

    public function deleteSelection($id = null)
    {
        return $this->BlockList->deleteSelection($this->_isRest(), $id);
    }
}
