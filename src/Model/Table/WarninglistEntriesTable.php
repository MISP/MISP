<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\ORM\Table;
use Cake\Validation\Validator;

class WarninglistEntriesTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        // $this->addBehavior('AuditLog');
        $this->belongsTo(
            'Warninglist',
            [
                'dependent' => true,
                'propertyName' => 'Warninglist'
            ]
        );
        $this->setDisplayField('value');
    }

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->notEmptyString('value')
            ->requirePresence(['value', 'warninglist_id'], 'create');
        return $validator;
    }
}
