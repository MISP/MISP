<?php
App::uses('AppModel', 'Model');

class DecayingModelMapping extends AppModel
{
    public $actsAs = array('Containable');

    public $validate = array(
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

    private $modelCache = [];

    public function resetMappingForModel($new_model, $user) {
        if (empty($new_model['model_id'])) {
            throw new NotFoundException(__('No Decaying Model with the provided ID exists'));
        }
        $this->deleteAll(array(
            'model_id' => $new_model['model_id']
        ));

        $data = array();
        foreach ($new_model['attribute_types'] as $type) {
            $to_save = array(
                'attribute_type' => $type,
                'model_id' => $new_model['model_id']
            );
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

    public function getAssociatedTypes($user, $model) {
        if (is_numeric($model)) {
            $model = $this->DecayingModel->fetchModel($user, $model, false);
            if (empty($model)) {
                throw new NotFoundException(__('No Decaying Model with the provided ID exists'));
            }
        }
        $decaying_model = isset($model['DecayingModel']) ? $model['DecayingModel'] : $model;
        if ($decaying_model['default']) {
            $associated_types = $decaying_model['attribute_types'];
        } else {
            $temp = $this->find('list', array(
                'conditions' => array(
                    'model_id' => $decaying_model['id']
                ),
                'recursive' => -1,
                'fields' => array('attribute_type')
            ));
            $associated_types = array_values($temp);
        }
        return $associated_types;
    }

    public function getAssociatedModels($user, $attribute_type = false) {
        $cacheKey = sprintf('%s', $attribute_type);
        if (isset($this->modelCache[$cacheKey])) {
            return $this->modelCache[$cacheKey];
        }
        $conditions = array(
            'OR' => array(
                'DecayingModel.org_id' => $user['org_id'],
                'DecayingModel.all_orgs' => true
            )
        );
        if ($attribute_type !== false) {
            $conditions['attribute_type'] = $attribute_type;
        }
        $associated_models = $this->find('all', array(
            'conditions' => $conditions,
            'recursive' => -1,
            'fields' => array('attribute_type', 'model_id'),
            'joins' => array( // joins has to be done to enforce ACL
                array(
                    'table' => 'decaying_models',
                    'alias' => 'DecayingModel',
                    'type' => 'INNER',
                    'conditions' => array(
                        'DecayingModel.id = DecayingModelMapping.model_id'
                    )
                )
            )
        ));
        // Also add default models to selection
        $default_models = $this->DecayingModel->fetchAllDefaultModel($user);
        $associated_default_models = array();
        foreach ($default_models as $i => $model) {
            $intersection = array_intersect($model['DecayingModel']['attribute_types'], array($attribute_type));
            if (count($intersection) > 0) {
                $associated_default_models[$attribute_type][] = $model['DecayingModel']['id'];
            }
        }
        $associated_models = Hash::combine($associated_models, '{n}.DecayingModelMapping.model_id', '{n}.DecayingModelMapping.model_id', '{n}.DecayingModelMapping.attribute_type');
        $models = array_merge_recursive($associated_default_models, $associated_models);
        $this->modelCache[$cacheKey] = $models;
        return $models;
    }

}
