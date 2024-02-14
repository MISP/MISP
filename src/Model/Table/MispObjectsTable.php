<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;

class MispObjects extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->setTable('objects');
    }
}
