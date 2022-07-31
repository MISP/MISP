<?php
App::uses('AppModel', 'Model');
App::uses('RandomTool', 'Tools');

class CorrelationValue extends AppModel
{
    public $recursive = -1;

    public $actsAs = array(
        'Containable'
    );

    public $validate = [
    ];

    public function getValueId($value)
    {
        $existingValue = $this->find('first', [
            'recursive' => -1,
            'conditions' => [
                'value' => $value
            ]
        ]);
        if (empty($existingValue)) {
            $this->create();
            if ($this->save(['value' => $value])) {
                return $this->id;
            }
        } else {
            return $existingValue['CorrelationValue']['id'];
        }
        return false;
    }

    public function getValue($id)
    {
        $existingValue = $this->find('first', [
            'recursive' => -1,
            'conditions' => [
                'id' => $id
            ]
        ]);
        if (!empty($existingValue)) {
            return $existingValue['CorrelationValue']['value'];
        }
        return false;
    }
}
