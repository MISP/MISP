<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\ORM\Table;
use Cake\Validation\Validator;

class TagCollectionTagsTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');
        $this->belongsTo(
            'TagCollection',
            [
                'dependent' => true
            ],
            'Tag',
            [
                'dependent' => true
            ],
        );
    }

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->requirePresence(['tag_collection_id', 'tag_id'], 'create');
        return $validator;
    }
}
