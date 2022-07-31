<?php
App::uses('AppModel', 'Model');
App::uses('RandomTool', 'Tools');

class OverCorrelatingValue extends AppModel
{
    public $recursive = -1;

    public $actsAs = array(
        'Containable'
    );

    public $validate = [
    ];

    public function block($value, $count)
    {
        $this->unblock($value);
        $this->create();
        $this->save(
            [
                'value' => $value,
                'occurrence' => $count
            ]
        );
    }

    public function unBlock($value)
    {
        $this->deleteAll(
            [
                'OverCorrelatingValue.value' => $value
            ]
        );
    }

    public function getLimit()
    {
        return Configure::check('MISP.correlation_limit') ? Configure::read('MISP.correlation_limit') : 20;
    }

    public function getOverCorrelations($query)
    {
        $data = $this->find('all', $query);
        $limit = $this->getLimit();
        foreach ($data as $k => $v) {
            if ($v['OverCorrelatingValue']['occurrence'] >= $limit) {
                $data[$k]['OverCorrelatingValue']['over_correlation'] = true;
            } else {
                $data[$k]['OverCorrelatingValue']['over_correlation'] = false;
            }
        }
        return $data;
    }

    public function checkValue($value)
    {
        $hit = $this->find('first', [
            'recursive' => -1,
            'conditions' => ['value' => $value],
            'fields' => ['id']
        ]);
        if (empty($hit)) {
            return false;
        }
        return true;
    }
}
