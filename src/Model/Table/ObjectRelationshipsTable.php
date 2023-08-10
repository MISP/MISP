<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\Validation\Validator;
use App\Lib\Tools\FileAccessTool;
use Cake\ORM\RulesChecker;
use Cake\ORM\Rule\IsUnique;

class ObjectRelationshipsTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');
        $this->addBehavior('JsonFields', [
            'fields' => ['format'],
        ]);
        $this->setDisplayField('name');
    }

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->notEmptyString('name')
            ->requirePresence(['name']);
        return $validator;
    }

    public function buildRules(RulesChecker $rules): RulesChecker
    {
        $rules->add($rules->isUnique(['name']));
        return $rules;
    }

    public function update()
    {
        $relationsFile = APP . '../libraries/object-templates/relationships/definition.json';
        if (file_exists($relationsFile)) {
            $relations = FileAccessTool::readJsonFromFile($relationsFile, true);
            if (!isset($relations['version'])) {
                $relations['version'] = 1;
            }
            $this->deleteAll(array('version <' => $relations['version']));
            foreach ($relations['values'] as $relation) {
                $relation['version'] = $relations['version'];
                $relationEntity = $this->newEntity($relation);
                $relationEntity->format = $relation['format'];
                $this->save($relationEntity);
            }
        }
        return true;
    }
}
