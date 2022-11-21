<?php
App::uses('AppController', 'Controller');

/**
 * @property AdminCrudComponent $AdminCrud
 */
class AllowedlistsController extends AppController
{
    public $components = array(
        'AdminCrud'
    );

    public $paginate = array(
        'limit' => 60,
        'order' => array(
            'Allowedlist.name' => 'ASC'
        )
    );

    public function admin_add()
    {
        $this->set('action', 'add');
        $this->AdminCrud->adminAdd();
    }

    public function admin_index()
    {
        $this->AdminCrud->adminIndex();
        $this->render('index');
    }

    public function admin_edit($id = null)
    {
        $this->AdminCrud->adminEdit($id);
        $this->set('action', 'edit');
        $this->set('id', $id);
        $this->render('admin_add');
    }

    public function admin_delete($id = null)
    {
        $this->AdminCrud->adminDelete($id);
    }

    public function index()
    {
        $this->recursive = 0;
        $this->set('list', $this->paginate());
    }
}
