<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;

class ServersTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');
    }
}
