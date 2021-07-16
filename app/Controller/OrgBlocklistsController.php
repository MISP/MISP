<?php
App::uses('AppController', 'Controller');

class OrgBlocklistsController extends AppController
{
    public $components = [
        'Session',
        'RequestHandler',
        'CRUD',
        'BlockList'
    ];

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
        'maxLimit' => 9999,
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
        $this->CRUD->add([]);
    }

    public function edit($id)
    {
        $this->CRUD->edit($id, []);
    }

    public function delete($id)
    {
        return $this->BlockList->delete($this->_isRest(), $id);
    }
}
