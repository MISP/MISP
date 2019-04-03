<?php

App::uses('AppController', 'Controller');

class DecayingModelMappingController extends AppController
{
    public $components = array('Security' ,'RequestHandler');

    public $belongsTo = array(
        'DecayingModel' => array(
            'className' => 'DecayingModel',
            'foreignKey' => 'id'
        )
    );

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

}
