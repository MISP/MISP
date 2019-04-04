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

    public function update($force=false) {
        if (!$this->_isSiteAdmin()) {
            throw new MethodNotAllowedException(_('You are not authorised to edit it.'));
        }

        if ($this->request->is('post')) {
            $this->DecayingModel->update($force);
            $message = 'Default decaying models updated';
            if ($this->_isRest()) {
                return $this->RestResponse->saveSuccessResponse('DecayingModel', 'update', false, $this->response->type(), $message);
            } else {
                $this->Flash->success($message);
                $this->redirect(array('controller' => 'decayingModel', 'action' => 'index'));
                // return $this->RestResponse->viewData($message, $this->response->type());
            }
        } else {
            throw new Exception(_("This method is not allowed"));
        }
    }

    public function view($id) {
        if (!$this->request->is('get')) {
            throw new Exception("This method is not allowed");
        }

        $decaying_model = $this->DecayingModel->checkAuthorisation($this->Auth->user(), $id, true);
        if (!$this->_isSiteAdmin() && !$decModel) {
            throw new MethodNotAllowedException(_('No Decaying Model with the provided ID exists, or you are not authorised to edit it.'));
        }
        $this->set('mayModify', true);
        $this->set('id', $id);
        $this->set('decaying_model', $decaying_model);
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
                throw new MethodNotAllowedException(_("The model must have a name"));
            }

            if ($this->DecayingModel->save($this->request->data)) {
                if ($this->request->is('ajax')) {
                    $saved = $this->DecayingModel->checkAuthorisation($this->Auth->user(), $this->DecayingModel->id);
                    $response = array('data' => $saved, 'action' => 'add');
                    return $this->RestResponse->viewData($response, $this->response->type());
                } else {
                    $this->Flash->success(_('The model has been saved.'));
                    $this->redirect(array('action' => 'index'));
                }
            }
        }
    }

    public function edit($id) {
        $decayingModel = $this->DecayingModel->checkAuthorisation($this->Auth->user(), $id);
        if (!$this->_isSiteAdmin() && !$decModel) {
            throw new NotFoundException(_('No Decaying Model with the provided ID exists, or you are not authorised to edit it.'));
        }
        $this->set('mayModify', true);

        if ($this->request->is('post') || $this->request->is('put')) {
            $this->request->data['DecayingModel']['id'] = $id;

            if (!isset($this->request->data['DecayingModel']['parameters'])) {
                $this->request->data['DecayingModel']['parameters'] = array();
            } else {
                if (!isset($this->request->data['DecayingModel']['parameters']['tau'])) {
                    $this->Flash->error(_('Invalid parameter `tau`.'));
                    return true;
                }
                if (!isset($this->request->data['DecayingModel']['parameters']['delta'])) {
                    $this->Flash->error(_('Invalid parameter `delta`.'));
                    return true;
                }
                if (!isset($this->request->data['DecayingModel']['parameters']['threshold'])) {
                    $this->Flash->error(_('Invalid parameter `threshold`.'));
                    return true;
                }
            }
            $this->request->data['DecayingModel']['parameters'] = json_encode($this->request->data['DecayingModel']['parameters']);

            $fieldList = array('name', 'description', 'parameters');
            if ($this->DecayingModel->save($this->request->data, true, $fieldList)) {
                if ($this->request->is('ajax')) {
                    $saved = $this->DecayingModel->checkAuthorisation($this->Auth->user(), $this->DecayingModel->id);
                    $response = array('data' => $saved, 'action' => 'edit');
                    return $this->RestResponse->viewData($response, $this->response->type());
                } else {
                    $this->Flash->success(_('The model has been saved.'));
                    $this->redirect(array('action' => 'index'));
                }
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
                throw new MethodNotAllowedException(_('No Decaying Model with the provided ID exists, or you are not authorised to edit it.'));
            }

            if ($this->DecayingModel->delete($id, true)) {
                $this->Flash->success(_('Decaying Model deleted.'));
                $this->redirect(array('action' => 'index'));
            } else {
                $this->Flash->error(_('The Decaying Model could not be deleted.'));
                $this->redirect(array('action' => 'index'));
            }
        }
    }

    public function decayingTool() {
        $parameters = array(
            'Tau' => array('value' => 30, 'step' => 1, 'max' => 365, 'greek' => 'τ', 'unit' => 'days', 'name' => 'Lifetime', 'info' => 'Lifetime of the attribute, or time after which the score will be 0'),
            'Delta' => array('value' => 0.3, 'step' => 0.1, 'max' => 10, 'greek' => 'δ', 'name' => 'Decay speed', 'info' => 'Decay speed at which an indicator will loose score'),
            'Threshold' => array('value' => 30, 'step' => 1, 'name' =>'Cutoff threshold', 'info' => 'Cutoff value at which an indicator will be marked as decayed instead of 0')
        );
        $types = $this->User->Event->Attribute->typeDefinitions;
        // $types = array_filter($types, function($v, $k) {
        //     return $v['to_ids'] == 1;
        // }, ARRAY_FILTER_USE_BOTH);
        $this->loadModel('ObjectTemplateElement');
        $objectTypes = $this->ObjectTemplateElement->getAllAvailableTypes();
        array_walk($objectTypes, function(&$key) {
            $key["isObject"] = true;
            $key["default_category"] = $key["category"];
        });
        $types = array_merge($types, $objectTypes);
        ksort($types);
        $savedDecayingModels = $this->DecayingModel->fetchAllowedModels($this->Auth->user());

        $this->set('parameters', $parameters);
        $this->set('types', $types);
        $this->set('savedModels', $savedDecayingModels);
    }

}
