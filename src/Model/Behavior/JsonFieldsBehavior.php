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

    public function afterMarshal(
        EventInterface $event,
        EntityInterface $entity,
        ArrayObject $data,
        ArrayObject $options
    ) {
        $config = $this->getConfig();

        foreach ($config['fields'] as $field => $fieldConfig) {
            if (!isset($data[$field]) && array_key_exists('default', $fieldConfig)) {
                $entity->set($field, $fieldConfig['default']);
            } else {
                $entity->set($field, $data[$field] ?? []);
            }
        }
    }

    public function beforeSave(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        $config = $this->getConfig();

        foreach ($config['fields'] as $field => $fieldConfig) {
            if (!$entity->has($field)) {
                continue;
            }
            $value = $entity->get($field) ?? [];
            $entity->set($field, JsonTool::encode($value));
        }
    }

    public function afterSave(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        $config = $this->getConfig();

        foreach ($config['fields'] as $field => $fieldConfig) {
            if ($entity[$field] !== null) {
                $entity[$field] = JsonTool::decode($entity[$field]);
            }
        }
    }

    public function beforeFind(EventInterface $event, Query $query, ArrayObject $options)
    {
        $config = $this->getConfig();

        $query->formatResults(
            function (CollectionInterface $results) use ($config) {
                return $results->map(
                    function ($row) use ($config) {
                        foreach ($config['fields'] as $field => $fieldConfig) {
                            if (isset($row[$field]) && !is_array($row[$field])) {
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
