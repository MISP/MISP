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
        'DecayingModel',
        'Attribute'
    );

    private $__default_type_mapping = array(
        'domain|ip' => 10,
        'ip-dst' => 10,
        'ip-dst|port' => 10,
        'ip-src' => 10,
        'ip-src|port' => 10,
    );

    private $__default_type_mapping_reverse = array();
    // private $default_type_mapping_reverse = array_flip($this->__default_type_mapping);

    private function __setup() {
        foreach ($this->__default_type_mapping as $type => $model_id) {
            if (!isset($this->__default_type_mapping_reverse[$model_id])) {
                $this->__default_type_mapping_reverse[$model_id] = array();
            }
            $this->__default_type_mapping_reverse[$model_id][] = $type;
        }
    }

    public function injectDefaultMapping(&$associated_types, $model_id) {
        $associated_types = array_merge($associated_types, $this->__default_type_mapping_reverse[$model_id]);
    }

    public function getAssociatedTypes($user, $model_id) {
        $this->__setup();
        $decaying_model = $this->DecayingModel->checkAuthorisation($user, $model_id);
        if (!$decaying_model) {
            $associated_types = array();
        } else {
            $conditions = array(
                'org_id' => $user['Organisation']['id'],
                'model_id' => $model_id
            );
            $associated_types = $this->find('all', array(
                'conditions' => $conditions,
                'recursive' => -1,
                'fields' => array('attribute_type')
            ));
            $this->injectDefaultMapping($associated_types, $model_id);
            // if (!empty($associated_types)) {
            //     $associated_types = $associated_types[0];
            // }
        }
        return $associated_types;
    }

}
