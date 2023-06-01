<?php

namespace App\Model\Behavior;

use Cake\ORM\Behavior;
use Cake\Event\EventInterface;
use Cake\Datasource\EntityInterface;
use ArrayObject;
use Cake\Collection\CollectionInterface;
use Cake\ORM\Query;
use App\Lib\Tools\JsonTool;

class JsonFieldsBehavior extends Behavior
{
    protected $_defaultConfig = [
        'fields' => []
    ];

    public function beforeSave(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        $config = $this->getConfig();

        foreach ($config['fields'] as $field) {
            $value = $entity->get($field);
            $entity->set($field, JsonTool::encode($value));
        }
    }

    public function beforeFind(EventInterface $event, Query $query, ArrayObject $options)
    {
        $config = $this->getConfig();

        $query->formatResults(
            function (CollectionInterface $results) use ($config) {
                return $results->map(
                    function ($row) use ($config) {
                        foreach ($config['fields'] as $field) {
                            $row[$field] = JsonTool::decode($row[$field]);
                        }
                        return $row;
                    }
                );
            },
            $query::APPEND
        );
    }
}
