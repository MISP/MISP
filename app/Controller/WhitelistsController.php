<?php

App::uses('AppController', 'Controller');

class WhitelistsController extends AppController
{
    public $components = array(
        'Security',
        'AdminCrud'
    );

    public $paginate = array(
            'limit' => 60,
            'order' => array(
                    'Whitelist.name' => 'ASC'
            )
    );

    public function admin_add()
    {
        if (!$this->userRole['perm_regexp_access']) {
            $this->redirect(array('controller' => 'regexp', 'action' => 'index', 'admin' => false));
        }
        $this->AdminCrud->adminAdd();
    }

    public function admin_index()
    {
        if (!$this->userRole['perm_regexp_access']) {
            $this->redirect(array('controller' => 'whitelists', 'action' => 'index', 'admin' => false));
        }
        $this->AdminCrud->adminIndex();
    }

    public function admin_edit($id = null)
    {
        if (!$this->userRole['perm_regexp_access']) {
            $this->redirect(array('controller' => 'whitelists', 'action' => 'index', 'admin' => false));
        }
        $this->AdminCrud->adminEdit($id);
    }

    public function admin_delete($id = null)
    {
        if (!$this->userRole['perm_regexp_access']) {
            $this->redirect(array('controller' => 'whitelists', 'action' => 'index', 'admin' => false));
        }
        $this->AdminCrud->adminDelete($id);
    }

    public function index()
    {
        $this->recursive = 0;
        $this->set('list', $this->paginate());
    }
}
