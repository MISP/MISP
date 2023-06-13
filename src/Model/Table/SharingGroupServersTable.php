<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;

class SharingGroupServersTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');

        $this->belongsTo(
            'Servers',
            [
                'foreignKey' => 'server_id',
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
