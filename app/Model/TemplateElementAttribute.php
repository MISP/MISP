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
