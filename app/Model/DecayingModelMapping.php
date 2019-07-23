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

    public function resetMappingForModel($new_model) {
        if (!isset($new_model['org_id'])) {
            $new_model['org_id'] = null;
        }
        $this->deleteAll(array(
            'DecayingModelMapping.org_id' => $new_model['org_id'],
            'model_id' => $new_model['model_id']
        ));

        $data = array();
        foreach ($new_model['attribute_types'] as $type) {
            $to_save = array(
                'attribute_type' => $type,
                'model_id' => $new_model['model_id']
            );
            if (!is_null($new_model['org_id'])) {
                $to_save['org_id'] = $new_model['org_id'];
            }
            $data[] = $to_save;
        }

        $result = $this->saveMany($data, array(
            'atomic' => true
        ));
        if ($result) {
            return $new_model['attribute_types'];
        } else {
            return array();
        }
    }

    public function getAssociatedTypes($user, $model_id) {
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
                        array('org_id' => $user['Organisation']['id']),
                        array('org_id' => null),
                    ),
                    'model_id' => $model_id
                ),
                'recursive' => -1,
                'fields' => array('attribute_type')
            ));
            $associated_types = array_values(array_unique(array_merge($associated_types, $temp)));
        }
        return $associated_types;
    }

    public function getAssociatedModels($user, $attribute_type = array()) {
        $conditions = array(
            'OR' => array(
                array('org_id' => $user['Organisation']['id']),
                array('org_id' => null),
            )
        );
        if (!empty($attribute_type)) {
            $conditions['attribute_type'] = $attribute_type;
        }
        $associated_models = $this->find('all', array(
            'conditions' => $conditions,
            'recursive' => -1,
            // 'group' => 'attribute_type',
            'fields' => array('attribute_type', 'model_id')
        ));
        $associated_models = Hash::combine($associated_models, '{n}.DecayingModelMapping.model_id', '{n}.DecayingModelMapping.model_id', '{n}.DecayingModelMapping.attribute_type');
        return $associated_models;
    }

}
