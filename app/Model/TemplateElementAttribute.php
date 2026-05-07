<?php

App::uses('AppModel', 'Model');

/**
 * @property MispAttribute $Attribute
 */
class TemplateElementAttribute extends AppModel
{
    public $actsAs = array('Containable');

    public $belongsTo = array('TemplateElement');

    public $validate = array(
            'name' => array(
                'valueNotEmpty' => array(
                    'rule' => array('valueNotEmpty'),
                ),
            ),
            'description' => array(
                'valueNotEmpty' => array(
                    'rule' => array('valueNotEmpty'),
                ),
            ),
            'category' => array(
                'notDefault' => array(
                    'rule'    => array('notDefaultCategory'),
                    'message' => 'Please choose a category, do not leave it on Select Category.'
                ),
                'valueNotEmpty' => array(
                    'rule' => array('valueNotEmpty'),
                    'message' => 'Please choose a type.'
                )
            ),
            'type' => array(
                'notDefault' => array(
                    'rule'    => array('notDefaultType'),
                    'message' => 'Please choose a type, do not leave it on Select Type.'
                 ),
                'valueNotEmpty' => array(
                    'rule' => array('valueNotEmpty'),
                    'message' => 'Please choose a type.'
                )
            ),
    );

    public function beforeValidate($options = array())
    {
        $MispAttribute = ClassRegistry::init('MispAttribute');

        if (isset($this->data['TemplateElementAttribute']['type']) && !array_key_exists($this->data['TemplateElementAttribute']['type'], $MispAttribute->typeDefinitions)) {
            $this->invalidate('type', 'Invalid type selected.');
        }

        if (isset($this->data['TemplateElementAttribute']['category']) && !array_key_exists($this->data['TemplateElementAttribute']['category'], $MispAttribute->categoryDefinitions)) {
            $this->invalidate('category', 'Invalid category selected.');
        }

        parent::beforeValidate();
    }

    public function notDefaultCategory($check)
    {
        return $check['category'] != 'Select Category';
    }

    public function notDefaultType($check)
    {
        return $check['type'] != 'Select Type';
    }
}
