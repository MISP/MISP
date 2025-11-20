<?php

App::uses('AppModel', 'Model');

class TemplateElementFile extends AppModel
{
    public $actsAs = array('Containable');
    public $belongsTo = array('TemplateElement');

    public $validate = array(
            'name' => array(
                'rule' => array('valueNotEmpty'),
                'message' => 'Please enter a Name',
            ),
            'description' => array(
                'rule' => array('valueNotEmpty'),
                'message' => 'Please enter a Description',
            ),
            'category' => array(
                'notDefault' => array(
                    'rule'    => array('notDefaultCategory'),
                    'message' => 'Please choose a category, do not leave it on Select Category.'
                ),
                'valueNotEmpty' => array(
                    'rule' => array('valueNotEmpty'),
                    'message' => 'Please choose a category.'
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
}
