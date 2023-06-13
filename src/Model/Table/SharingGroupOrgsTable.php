<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;

class SharingGroupOrgsTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');

        $this->belongsTo(
            'Organisations',
            [
                'foreignKey' => 'org_id',
            ]
        );

        $this->belongsTo(
            'SharingGroups',
            [
                'foreignKey' => 'sharing_group_id',
            ]
        );
    }
}
