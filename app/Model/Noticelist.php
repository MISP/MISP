<?php
App::uses('AppModel', 'Model');
class Noticelist extends AppModel
{
    public $useTable = 'noticelists';

    public $recursive = -1;

    public $actsAs = array(
            'Containable',
    );

    public $validate = array(
        'name' => array(
            'rule' => array('valueNotEmpty'),
        ),
        'version' => array(
            'rule' => array('numeric'),
        ),
    );

    public $hasMany = array(
            'NoticelistEntry' => array(
                'dependent' => true
            )
    );

    private $__entries = array();

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        $this->data['Noticelist']['ref'] = json_encode($this->data['Noticelist']['ref']);
        $this->data['Noticelist']['geographical_area'] = json_encode($this->data['Noticelist']['geographical_area']);
        return true;
    }

    public function update()
    {
        $directories = glob(APP . 'files' . DS . 'noticelists' . DS . 'lists' . DS . '*', GLOB_ONLYDIR);
        $updated = array();
        foreach ($directories as $dir) {
            $file = new File($dir . DS . 'list.json');
            $list = json_decode($file->read(), true);
            $file->close();
            if (!isset($list['version'])) {
                $list['version'] = 1;
            }
            $current = $this->find('first', array(
                    'conditions' => array('name' => $list['name']),
                    'recursive' => -1,
                    'fields' => array('*')
            ));
            if (empty($current) || $list['version'] > $current['Noticelist']['version']) {
                $result = $this->__updateList($list, $current);
                if (is_numeric($result)) {
                    $updated['success'][$result] = array('name' => $list['name'], 'new' => $list['version']);
                    if (!empty($current)) {
                        $updated['success'][$result]['old'] = $current['Noticelist']['version'];
                    }
                } else {
                    $updated['fails'][] = array('name' => $list['name'], 'fail' => json_encode($result));
                }
            }
        }
        if (empty($updated)) {
            return 'All noticelists are up to date already.';
        }
        return $updated;
    }

    private function __updateList($list, $current)
    {
        $list['enabled'] = 0;
        $noticelist = array();
        if (!empty($current)) {
            if ($current['Noticelist']['enabled']) {
                $list['enabled'] = 1;
            }
            $this->quickDelete($current['Noticelist']['id']);
        }
        $fieldsToSave = array('name', 'expanded_name', 'ref', 'geographical_area', 'version', 'enabled');
        foreach ($fieldsToSave as $fieldToSave) {
            $noticelist['Noticelist'][$fieldToSave] = $list[$fieldToSave];
        }
        $this->create();
        if ($this->save($noticelist)) {
            $db = $this->getDataSource();
            $values = array();
            foreach ($list['notice'] as $value) {
                if (!empty($value)) {
                    $values[] = array('data' => $value, 'noticelist_id' => $this->id);
                }
            }
            unset($list['notice']);
            foreach ($values as $value) {
                $this->NoticelistEntry->create();
                $this->NoticelistEntry->save($value);
            }
            return $this->id;
        } else {
            return $this->validationErrors;
        }
    }

    public function getTriggerData($scope = 'attribute')
    {
        $noticelists = $this->find('all', array(
            'conditions' => array('enabled' => 1),
            'recursive' => -1,
            'contain' => 'NoticelistEntry'
        ));
        $noticelist_triggers = array();
        $validTriggers = array(
            'attribute' => array(
                'category',
                'type'
            )
        );
        foreach ($noticelists as $noticelist) {
            foreach ($noticelist['NoticelistEntry'] as $entry) {
                if (in_array('attribute', $entry['data']['scope'])) {
                    foreach ($entry['data']['field'] as $data_field) {
                        if (in_array($data_field, $validTriggers[$scope])) {
                            foreach ($entry['data']['value'] as $value) {
                                $noticelist_triggers[$data_field][$value][] = array(
                                    'message' => $entry['data']['message'],
                                    'list_id' => $noticelist['Noticelist']['id'],
                                    'list_name' => $noticelist['Noticelist']['name']
                                );
                            }
                        }
                    }
                }
            }
        }
        return $noticelist_triggers;
    }
}
