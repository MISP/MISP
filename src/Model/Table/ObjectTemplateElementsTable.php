<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;

class ObjectTemplateElementsTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');
        $this->addBehavior(
            'JsonFields',
            [
                'fields' => ['categories' => [], 'values_list' => [], 'sane_default'=> []],
            ]
        );
        $this->setDisplayField('object_relation');
    }

    public function getAllAvailableTypes()
    {
        $temp = $this->find(
            'all',
            [
                'recursive' => -1,
                'fields' => ['object_relation as type', 'description AS desc', 'categories'],
                'group' => ['object_relation', 'description', 'categories']
            ]
        );
        $res = [];
        foreach ($temp as $type) {
            $res[$type['ObjectTemplateElement']['type']] = [
                'desc' => $type['ObjectTemplateElement']['desc'],
                'category' => $type['ObjectTemplateElement']['categories']
            ];
        }
        return $res;
    }
}
