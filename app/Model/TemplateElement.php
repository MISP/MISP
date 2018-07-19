<?php

App::uses('AppModel', 'Model');

class TemplateElement extends AppModel
{
    public $actsAs = array('Containable');

    public $hasMany = array(
        'TemplateElementAttribute' => array(
            'dependent' => true
        ),
        'TemplateElementText' => array(
            'dependent' => true
        ),
        'TemplateElementFile' => array(
            'dependent' => true
        )
    );

    public $belongsTo = array('Template');

    public function lastPosition($template_id)
    {
        $result = $this->find('first', array(
            'fields' => array('MAX(position) AS pos', 'id', 'template_id'),
            'conditions' => array('template_id' => $template_id),
            'order' => array('id'),
            'group' => array('id', 'template_id')
        ));
        if (empty($result)) {
            return 0;
        }
        return $result[0]['pos'];
    }
}
