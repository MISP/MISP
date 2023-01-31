<?php

namespace Tags\Model\Table;

use App\Model\Table\AppTable;
use Cake\Validation\Validator;

class TaggedTable extends AppTable
{
    protected $_accessible = [
        'id' => false
    ];

    public function initialize(array $config): void
    {
        $this->setTable('tags_tagged');
        $this->belongsTo('Tags', [
            'className' => 'Tags.Tags',
            'foreignKey' => 'tag_id',
            'propertyName' => 'tag',
        ]);
        $this->addBehavior('Timestamp');
    }

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->notBlank('fk_model')
            ->notBlank('fk_id')
            ->notBlank('tag_id');
        return $validator;
    }
}
