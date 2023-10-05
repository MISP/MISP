<?php

namespace App\Model\Table;

use App\Lib\Tools\FileAccessTool;
use App\Model\Entity\NoticelistEntry;
use App\Model\Table\AppTable;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\Validation\Validator;

class NoticelistsTable extends AppTable
{
    use LocatorAwareTrait;

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');
        $this->addBehavior(
            'JsonFields',
            [
                'fields' => ['ref', 'geographical_area'],
            ]
        );

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
        $directories = glob(APP . '..' . DS . 'libraries' . DS . 'misp-noticelist' . DS . 'lists' . DS . '*', GLOB_ONLYDIR);
        $updated = [];
        foreach ($directories as $dir) {
            $list = FileAccessTool::readJsonFromFile($dir . DS . 'list.json');
            if (!isset($list['version'])) {
                $list['version'] = 1;
            }
            $current = $this->find(
                'all',
                [
                    'conditions' => ['name' => $list['name']],
                    'recursive' => -1
                ]
            )->first();
            if (empty($current) || $list['version'] > $current['version']) {
                $result = $this->__updateList($list, $current);
                if (is_numeric($result)) {
                    $updated['success'][$result] = ['name' => $list['name'], 'new' => $list['version']];
                    if (!empty($current)) {
                        $updated['success'][$result]['old'] = $current['version'];
                    }
                } else {
                    $updated['fails'][] = ['name' => $list['name'], 'fail' => json_encode($result)];
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
        $noticelist = [];
        if (!empty($current)) {
            if ($current['enabled']) {
                $list['enabled'] = 1;
            }
            $this->quickDelete($current['id']);
        }
        $fieldsToSave = ['name', 'expanded_name', 'ref', 'geographical_area', 'version', 'enabled'];
        foreach ($fieldsToSave as $fieldToSave) {
            $noticelist[$fieldToSave] = $list[$fieldToSave];
        }
        $noticelistEntity = $this->newEntity($noticelist);
        $noticelistEntity->ref = $noticelist['ref'];
        $noticelistEntity->geographical_area = $noticelist['geographical_area'];
        $result = $this->save($noticelistEntity);
        if ($result) {
            $values = [];
            foreach ($list['notice'] as $value) {
                if (!empty($value)) {
                    $values[] = ['data' => $value, 'noticelist_id' => $result->id];
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
        $noticelists = $this->find(
            'all',
            [
                'conditions' => ['enabled' => 1],
                'recursive' => -1,
                'contain' => 'NoticelistEntry'
            ]
        );
        $noticelist_triggers = [];
        $validTriggers = [
            'attribute' => [
                'category',
                'type'
            ]
        ];
        foreach ($noticelists as $noticelist) {
            foreach ($noticelist['NoticelistEntry'] as $entry) {
                if (in_array('attribute', $entry['data']['scope'])) {
                    foreach ($entry['data']['field'] as $data_field) {
                        if (in_array($data_field, $validTriggers[$scope])) {
                            foreach ($entry['data']['value'] as $value) {
                                $noticelist_triggers[$data_field][$value][] = [
                                    'message' => $entry['data']['message'],
                                    'list_id' => $noticelist['id'],
                                    'list_name' => $noticelist['name']
                                ];
                            }
                        }
                    }
                }
            }
        }
        return $noticelist_triggers;
    }
}
