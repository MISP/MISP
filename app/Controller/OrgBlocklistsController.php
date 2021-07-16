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
        $this->CRUD->index([]);

        if ($this->IndexFilter->isRest()) {
            return $this->restResponsePayload;
        }
        $this->set('menuData', ['menuList' => 'admin', 'menuItem' => 'orgBlocklists']);
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
