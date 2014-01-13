<?php
App::uses('AppController', 'Controller');

class OrganisationsController extends AppController {

    public function admin_index() {

        if(!empty($this->request->data)){
            $redirect = array('action' => 'index');
            foreach($this->request->data['Organisation'] as $k => $v){
                if(!empty($v)){
                    $redirect[$k] = $v;
                }
            }
            $this->redirect($redirect);
        }
        $cond = array();

        if(!empty($this->passedArgs['key'])){
            $cond += array('Organisation.name LIKE' => '%'.$this->passedArgs['key'].'%');
        }

        $this->paginate = array('conditions' => $cond);
        $this->set('organisations', $this->paginate());
    }


    public function admin_add() {
        if ($this->request->is('post')) {
            $this->Organisation->create();
            if ($this->Organisation->save($this->request->data)) {
                $this->Session->setFlash(__('The organisation has been saved'), 'flash_message', array('type' => 'alert-success'));
                $this->redirect(array('action' => 'index'));
            } else {
                $this->Session->setFlash(__('The organisation could not be saved. Please, try again.'), 'flash_message', array('type' => 'alert-error'));
            }
        }
        $sharingGroups = $this->Organisation->SharingGroup->find('list');
        $this->set(compact('sharingGroups'));
    }

    public function admin_edit($id = null) {
        if (!$this->Organisation->exists($id)) {
            throw new NotFoundException(__('Invalid organisation'));
        }
        if ($this->request->is('post') || $this->request->is('put')) {
            if ($this->Organisation->save($this->request->data)) {
                $this->Session->setFlash(__('The organisation has been saved'), 'flash_message', array('type' => 'alert-success'));
                $this->redirect(array('action' => 'index'));
            } else {
                $this->Session->setFlash(__('The organisation could not be saved. Please, try again.'), 'flash_message', array('type' => 'alert-error'));
            }
        } else {
            $options = array('conditions' => array('Organisation.' . $this->Organisation->primaryKey => $id));
            $this->request->data = $this->Organisation->find('first', $options);
        }
        $sharingGroups = $this->Organisation->SharingGroup->find('list');
        $this->set(compact('sharingGroups'));
    }

    public function admin_delete($id = null) {
        $this->Organisation->id = $id;
        if (!$this->Organisation->exists()) {
            throw new NotFoundException(__('Invalid organisation'));
        }
        $this->request->onlyAllow('post', 'delete');
        if ($this->Organisation->delete()) {
            $this->Session->setFlash(__('Organisation deleted'), 'flash_message', array('type' => 'alert-success'));
            $this->redirect(array('action' => 'index'));
        }
        $this->Session->setFlash(__('Organisation was not deleted'), 'flash_message', array('type' => 'alert-error'));
        $this->redirect(array('action' => 'index'));
    }
}
