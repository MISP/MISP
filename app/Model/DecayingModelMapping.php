<?php
App::uses('AppModel', 'Model');

class DecayingModelMapping extends AppModel
{
    public $actsAs = array('Containable');

    public $validate = array(
        'org_id' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
        ),
        'attribute_type' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
        ),
        'model_id' => array(
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
        ),
    );

    public $belongsTo = array(
        'DecayingModel' => array(
            'className' => 'DecayingModel',
            'foreignKey' => 'id'
        )
    );

    private $__default_type_mapping_reverse = array();
    // private $default_type_mapping_reverse = array_flip($this->__default_type_mapping);

    private function __setup() {
        // foreach ($this->__default_type_mapping as $type => $model_id) {
        //     if (!isset($this->__default_type_mapping_reverse[$model_id])) {
        //         $this->__default_type_mapping_reverse[$model_id] = array();
        //     }
        //     $this->__default_type_mapping_reverse[$model_id][] = $type;
        // }
    }

    // Delete all DEFAULT mapping associated to the model and re-create them
    public function resetMappingFromDefaultModel($new_model) {
        $this->deleteAll(array(
            'DecayingModelMapping.org_id' => null,
            'model_id' => $new_model['id']
        ));

        foreach ($new_model['attribute_types'] as $type) {
            $this->create();
            $to_save = array(
                'attribute_type' => $type,
                'model_id' => $new_model['id']
            );
            $this->save($to_save);
        }
    }

    public function getAssociatedTypes($user, $model_id) {
        $this->__setup();
        $decaying_model = $this->DecayingModel->find('first', array(
            'conditions' => array('id' => $model_id),
            'recursive' => -1,
        ));
        if (empty($decaying_model)) {
            $associated_types = array();
        } else {
            $decaying_model = $decaying_model['DecayingModel'];
            $associated_types = $decaying_model['attribute_types'];
            $temp = $this->find('list', array(
                'conditions' => array(
                    'OR' => array(
                        'org_id' => $user['Organisation']['id'],
                        'org_id' => NULL,
                    ),
                    'model_id' => $model_id
                ),
                'recursive' => -1,
                'fields' => array('attribute_type')
            ));
            $associated_types = array_unique(array_merge($associated_types, $temp));
        }
        return $associated_types;
    }

    public function getAssociatedModels($user, $attribute_type) {
        $associated_models = $this->find('all', array(
            'conditions' => array(
                'OR' => array(
                    'org_id' => $user['Organisation']['id'],
                    'org_id' => NULL,
                ),
                'model_id' => $attribute_type
            ),
            'recursive' => -1,
            'fields' => array('attribute_type')
        ));
        return $associated_models;
    }

}
