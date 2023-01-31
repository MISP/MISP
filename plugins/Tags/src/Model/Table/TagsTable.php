<?php

namespace Tags\Model\Table;

use App\Model\Table\AppTable;
use Cake\Validation\Validator;

class TagsTable extends AppTable
{
    protected $_accessible = [
        'id' => false
    ];

    public function initialize(array $config): void
    {
        $this->setTable('tags_tags');
        $this->setDisplayField('name'); // Change to name?
        $this->addBehavior('Timestamp');
    }

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->notBlank('name');
        return $validator;
    }
}
