<?php
namespace App\Model\Behavior;

use Cake\ORM\Behavior;
use Cake\Event\EventInterface;
use Cake\Datasource\EntityInterface;
use ArrayObject;
use Cake\Utility\Text;

class UUIDBehavior extends Behavior
{
    public function beforeSave(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        if ($entity->isNew() && empty($entity['uuid'])) {
            $entity['uuid'] = Text::uuid();
        }
    }
}
