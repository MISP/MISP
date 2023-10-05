<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;

class ObjectTemplateElementsTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');
        $this->addBehavior('JsonFields', [
            'fields' => ['categories', 'values_list', 'sane_default'],
        ]);
        $this->setDisplayField('object_relation');
    }

    public function getAllAvailableTypes()
    {
        $temp = $this->find('all', array(
            'recursive' => -1,
            'fields' => array('object_relation as type', 'description AS desc', 'categories'),
            'group' => array('object_relation', 'description', 'categories')
        ));
        $res = array();
        foreach ($temp as $type) {
            $res[$type['ObjectTemplateElement']['type']] = array(
                'desc' => $type['ObjectTemplateElement']['desc'],
                'category' => $type['ObjectTemplateElement']['categories']
            );
        }
        return $res;
    }
}
