<?php

App::uses('AppController', 'Controller');

class DecayingModelController extends AppController
{
    public $components = array('Security' ,'RequestHandler');

    public $paginate = array(
            'limit' => 50,
            'order' => array(
                    'DecayingModel.name' => 'asc'
            )
    );

    public function view($id) {
        if (!$this->request->is('get')) {
            throw new Exception("This method is not allowed");
        }

        $decayingModel = $this->DecayingModel->checkAuthorisation($this->Auth->user(), $id);
        if (!$this->_isSiteAdmin() && !$decModel) {
            throw new MethodNotAllowedException('No Decaying Model with the provided ID exists, or you are not authorised to edit it.');
        }
        $this->set('mayModify', true);
        $this->set('id', $id);
        $this->set('decayingModel', $decayingModel);
    }

    public function index() {
        $conditions = array();
        if (!$this->_isSiteAdmin()) {
            $conditions['OR'] = array('org_id' => $this->Auth->user('Organisation')['id']);
        }
        if (!$this->_isSiteAdmin()) {
            $this->paginate = Set::merge($this->paginate, array(
                    'conditions' => $conditions
            ));
        }
        $this->set('decayingModel', $this->paginate());
    }

    public function add() {
        if ($this->request->is('post')) {
            if (!isset($this->request->data['DecayingModel']['org_id'])) {
                $this->request->data['DecayingModel']['org_id'] = $this->Auth->user()['org_id'];
            }

            if (empty($this->request->data['DecayingModel']['name'])) {
                throw new MethodNotAllowedException("The model must have a name");

            }

            if ($this->DecayingModel->save($this->request->data)) {
                $this->Flash->success('The model has been saved.');
                $this->redirect(array('action' => 'index'));
            }
        }
    }

    public function edit($id) {
        $decayingModel = $this->DecayingModel->checkAuthorisation($this->Auth->user(), $id);
        if (!$this->_isSiteAdmin() && !$decModel) {
            throw new MethodNotAllowedException('No Decaying Model with the provided ID exists, or you are not authorised to edit it.');
        }
        $this->set('mayModify', true);

        if ($this->request->is('post')) {
            if (!isset($this->request->data['DecayingModel']['org_id'])) {
                $this->request->data['DecayingModel']['org_id'] = $this->Auth->user()['org_id'];
            }
            $this->request->data['DecayingModel']['id'] = $id;

            if ($this->DecayingModel->save($this->request->data)) {
                $this->Flash->success('The model has been saved.');
                $this->redirect(array('action' => 'index'));
            }
        }
        $this->request->data = $decayingModel;
        $this->set('id', $id);
        $this->set('decayingModel', $decayingModel);
    }

    public function delete($id) {
        if ($this->request->is('post')) {
            $decayingModel = $this->DecayingModel->checkAuthorisation($this->Auth->user(), $id);
            if (!$this->_isSiteAdmin() && !$decModel) {
                throw new MethodNotAllowedException('No Decaying Model with the provided ID exists, or you are not authorised to edit it.');
            }

            if ($this->DecayingModel->delete($id, true)) {
                $this->Flash->success('Decaying Model deleted.');
                $this->redirect(array('action' => 'index'));
            } else {
                $this->Flash->error('The Decaying Model could not be deleted.');
                $this->redirect(array('action' => 'index'));
            }
        }
    }

    public function decayingTool() {
        $parameters = array(
            'Tau' => array('value' => 30, 'step' => 1, 'max' => 365, 'greek' => 'τ', 'unit' => 'days', 'info' => 'Lifetime withouth threshold'),
            'Delta' => array('value' => 0.3, 'step' => 0.1, 'max' => 10, 'greek' => 'δ', 'info' => 'Decay speed'),
            'Threshold' => array('value' => 30, 'step' => 1, 'info' => 'Cut-off value to expire')
        );
        $types = $this->User->Event->Attribute->typeDefinitions;
        $types = array_filter($types, function($v, $k) {
            return $v['to_ids'] == 1;
        }, ARRAY_FILTER_USE_BOTH);
        ksort($types);
        $savedDecayingModels = $this->DecayingModel->fetchAllowedModels($this->Auth->user());

        $this->set('parameters', $parameters);
        $this->set('types', $types);
        $this->set('savedModels', $savedDecayingModels);
    }

}
