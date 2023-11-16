<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;

class NoticelistEntriesTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior(
            'JsonFields',
            [
                'fields' => ['data' => []],
            ]
        );
    }
}
