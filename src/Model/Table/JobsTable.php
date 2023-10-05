<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;

class JobsTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);

        $this->setDisplayField('name');
    }
}
