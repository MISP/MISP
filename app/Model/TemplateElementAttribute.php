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
                'rule'    => array('comparison', '!=', 'Select Category'),
                'message' => 'Please choose a category.'
            ),
            'type' => array(
                'rule'    => array('comparison', '!=', 'Select Type'),
                'message' => 'Please choose a type.'
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
}
