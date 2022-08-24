<?php
App::uses('AppModel', 'Model');

class CorrelationValue extends AppModel
{
    public $recursive = -1;

    /**
     * @param string $value
     * @return int
     */
    public function getValueId($value)
    {
        // index is 191 long, missing the existing value lookup can lead to a duplicate entry
        $value = mb_substr($value, 0, 191);
        $existingValue = $this->find('first', [
            'recursive' => -1,
            'fields' => ['id'],
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
                    'fields' => ['id'],
                    'conditions' => [
                        'value' => $value
                    ]
                ]);
                return $existingValue['CorrelationValue']['id'];
            }
        } else {
            return $existingValue['CorrelationValue']['id'];
        }
    }

    public function getValue($id)
    {
        $existingValue = $this->find('first', [
            'recursive' => -1,
            'fields' => ['value'],
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
