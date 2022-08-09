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
        // index is 191 long, missing the existing value lookup can lead to a duplicate entry
        $value = mb_substr($value, 0, 191);
        $existingValue = $this->find('first', [
            'recursive' => -1,
            'conditions' => [
                'value' => $value
            ]
        ]);
        if (empty($existingValue)) {
            $this->create();
            try {
                $this->save(['value' => $value]);
                return $this->id;
            } catch (Exception $e) {
                $existingValue = $this->find('first', [
                    'recursive' => -1,
                    'conditions' => [
                        'value' => $value
                    ]
                ]);
                return $existingValue['ExistingValue']['id'];
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
