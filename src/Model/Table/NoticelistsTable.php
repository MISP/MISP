<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\Validation\Validator;
use App\Lib\Tools\FileAccessTool;
use App\Model\Entity\Noticelist;
use App\Model\Entity\NoticelistEntry;
use Cake\ORM\Locator\LocatorAwareTrait;

class NoticelistsTable extends AppTable
{
    use LocatorAwareTrait;

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');
        $this->addBehavior('JsonFields', [
            'fields' => ['ref', 'geographical_area'],
        ]);

        $this->hasMany(
            'NoticelistEntries',
            [
                'dependent' => true,
                'propertyName' => 'NoticelistEntry',
            ]
        );
    }

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->requirePresence(['name'], 'create')
            ->add('version', 'numeric');

        return $validator;
    }

    public function update()
    {
        $directories = glob(APP . '..' . DS . 'libraries' . DS . 'noticelists' . DS . 'lists' . DS . '*', GLOB_ONLYDIR);
        $updated = array();
        foreach ($directories as $dir) {
            $list = FileAccessTool::readJsonFromFile($dir . DS . 'list.json');
            if (!isset($list['version'])) {
                $list['version'] = 1;
            }
            $current = $this->find('all', array(
                'conditions' => array('name' => $list['name']),
                'recursive' => -1
            ))->first();
            if (empty($current) || $list['version'] > $current['version']) {
                $result = $this->__updateList($list, $current);
                if (is_numeric($result)) {
                    $updated['success'][$result] = array('name' => $list['name'], 'new' => $list['version']);
                    if (!empty($current)) {
                        $updated['success'][$result]['old'] = $current['version'];
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
            if ($current['enabled']) {
                $list['enabled'] = 1;
            }
            $this->quickDelete($current['id']);
        }
        $fieldsToSave = array('name', 'expanded_name', 'ref', 'geographical_area', 'version', 'enabled');
        foreach ($fieldsToSave as $fieldToSave) {
            $noticelist[$fieldToSave] = $list[$fieldToSave];
        }
        $noticelist = new Noticelist($noticelist);
        $result = $this->save($noticelist);
        if ($result) {
            $values = array();
            foreach ($list['notice'] as $value) {
                if (!empty($value)) {
                    $values[] = array('data' => $value, 'noticelist_id' => $result->id);
                }
            }
            unset($list['notice']);
            $NoticelistEntries = $this->fetchTable('NoticelistEntries');
            foreach ($values as $value) {
                $entry = new NoticelistEntry($value);
                $NoticelistEntries->save($entry);
            }
            return $result->id;
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
                                    'list_id' => $noticelist['id'],
                                    'list_name' => $noticelist['name']
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
