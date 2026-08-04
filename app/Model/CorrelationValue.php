<?php
App::uses('AppModel', 'Model');

class CorrelationValue extends AppModel
{
    public $recursive = -1;

    /**
     * @param array $correlations
     * @param string|int $valueIndex
     * @return void
     */
    public function replaceValueWithId(array &$correlations, $valueIndex)
    {
        $values = array_column($correlations, $valueIndex);
        $valueIds = $this->getIds($values);

        foreach ($correlations as &$correlation) {
            $value = mb_substr($correlation[$valueIndex], 0, 191);
            $correlation[$valueIndex] = (int)$valueIds[$value];
        }
    }

    /**
     * @param array $values
     * @return array Value in key, value ID in value
     */
    private function getIds(array $values)
    {
        foreach ($values as &$value) {
            $value = mb_substr($value, 0, 191);
        }
        $values = array_unique($values, SORT_REGULAR); // Remove duplicate values
        $existingValues = $this->find('list', [
            'recursive' => -1,
            'callbacks' => false,
            'fields' => ['value', 'id'],
            'conditions' => [
                'value' => $values,
            ],
        ]);

        $notExistValues = array_diff($values, array_keys($existingValues));
        if (!empty($notExistValues)) {
            $this->getDataSource()->begin();
            foreach ($notExistValues as $notExistValue) {
                $this->create();
                try {
                    $this->save(['value' => $notExistValue], [
                        'callbacks' => false,
                        'validate' => false,
                    ]);
                    $existingValues[$notExistValue] = $this->id;
                } catch (Exception $e) {
                    $existingValues[$notExistValue] = $this->getValueId($notExistValue);
                }
            }
            $this->getDataSource()->commit();
        }

        return $existingValues;
    }

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
