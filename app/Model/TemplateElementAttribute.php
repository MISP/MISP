<?php

App::uses('AppModel', 'Model');

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
        parent::beforeValidate();
    }
}
