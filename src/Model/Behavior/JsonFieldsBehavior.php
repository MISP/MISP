<?php

namespace App\Model\Behavior;

use App\Lib\Tools\JsonTool;
use ArrayObject;
use Cake\Collection\CollectionInterface;
use Cake\Datasource\EntityInterface;
use Cake\Event\EventInterface;
use Cake\ORM\Behavior;
use Cake\ORM\Query;

class JsonFieldsBehavior extends Behavior
{
    protected $_defaultConfig = [
        'fields' => []
    ];

    public function beforeSave(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        $config = $this->getConfig();

        foreach ($config['fields'] as $field) {
            if (!$entity->has($field)) {
                continue;
            }
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
                            if (isset($row[$field])) {
                                $row[$field] = JsonTool::decode($row[$field]);
                            }
                        }
                        return $row;
                    }
                );
            },
            $query::APPEND
        );
    }
}
