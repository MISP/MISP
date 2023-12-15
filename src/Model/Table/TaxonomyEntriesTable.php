<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\Core\Configure;
use Cake\Validation\Validator;
use Exception;
use App\Lib\Tools\ColourPaletteTool;
use App\Lib\Tools\FileAccessTool;
use App\Lib\Tools\RedisTool;
use Cake\Utility\Hash;
use Cake\Datasource\EntityInterface;
use Cake\Event\Event;
use Cake\Event\EventInterface;
use ArrayObject;

class TaxonomyEntriesTable extends AppTable
{
    public function initialize(array $config): void
    {
        $this->setDisplayField('name');

        $this->belongsTo(
            'TaxonomyPredicates',
            [
                'className' => 'TaxonomyPredicates',
                'foreignKey' => 'taxonomy_predicate_id',
                'propertyName' => 'TaxonomyPredicate',
            ]
        );
    }

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->requirePresence(['value', 'expanded'], 'create');

        return $validator;
    }

    function beforeMarshal(EventInterface $event, ArrayObject $data, ArrayObject $options)
    {
        if (empty($data['expanded'])) {
            $data['expanded'] = $data['value'];
        }
    }
}
