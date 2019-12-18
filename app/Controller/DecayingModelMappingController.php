<?php

App::uses('AppController', 'Controller');

class DecayingModelMappingController extends AppController
{
    public $components = array('Security' ,'RequestHandler');

    public $paginate = array(
            'limit' => 50,
            'order' => array(
                    'DecayingModel.name' => 'asc'
            )
    );

    public function viewAssociatedTypes($model_id) {
        $associated_types = $this->DecayingModelMapping->getAssociatedTypes($this->Auth->user(), $model_id);
        return $this->RestResponse->viewData($associated_types, $this->response->type());
    }


    public function linkAttributeTypeToModel($model_id) {
        $model = $this->DecayingModelMapping->DecayingModel->fetchModel($this->Auth->user(), $model_id);
        if (empty($model)) {
            throw new NotFoundException(__('No Decaying Model with the provided ID exists'));
        }

        if ($this->request->is('post') || $this->request->is('put')) {
            $this->request->data['DecayingModelMapping']['model_id'] = $model_id;
            if (!isset($this->request->data['DecayingModelMapping']['org_id'])) {
                $this->request->data['DecayingModelMapping']['org_id'] = $this->Auth->user()['org_id'];
            }
            if (empty($this->request->data['DecayingModelMapping']['attributetypes'])) {
                throw new MethodNotAllowedException(_("The model must link to at least one attribute type"));
            } else {
                $decoded = json_decode($this->request->data['DecayingModelMapping']['attributetypes'], true);
                if ($decoded === null) {
                    throw new MethodNotAllowedException(_("Invalid JSON: attribute type"));
                }
                $this->request->data['DecayingModelMapping']['attribute_types'] = $decoded;
                unset($this->request->data['DecayingModelMapping']['attributetypes']);
            }

            $response = $this->DecayingModelMapping->resetMappingForModel($this->request->data['DecayingModelMapping'], $this->Auth->user());
            return $this->RestResponse->viewData($response, $this->response->type());
        } else {
            $this->set('model_id', $model_id);
        }
    }

}
