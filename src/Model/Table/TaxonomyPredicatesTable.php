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

class TaxonomyPredicatesTable extends AppTable
{
    public function initialize(array $config): void
    {
        $this->setDisplayField('name');

        $this->hasMany(
            'TaxonomyEntries',
            [
                'className' => 'TaxonomyEntries',
                'foreignKey' => 'taxonomy_predicate_id',
                'propertyName' => 'TaxonomyEntry',
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
