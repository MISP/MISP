<?php
declare(strict_types=1);

namespace App\Model\Behavior;

use ArrayObject;
use Cake\Datasource\EntityInterface;
use Cake\Event\EventInterface;
use Cake\ORM\Behavior;
use Cake\Utility\Text;
use Cake\Validation\Validator;

class UUIDBehavior extends Behavior
{
    /**
     * beforeSave
     *
     * @param  \Cake\Event\EventInterface $event the efent
     * @param  \Cake\Datasource\EntityInterface; $entity the entity
     * @param  array $options extra options
     * @return void
     */
    public function beforeSave(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        if ($entity->isNew() && empty($entity['uuid'])) {
            $entity['uuid'] = Text::uuid();
        }
    }

    /**
     * buildValidator
     *
     * @param  \Cake\Event\EventInterface $event the event
     * @param  \Cake\Validation\Validator $validator the validator
     * @param  string $name the string to validate
     * @return \Cake\Validation\Validator
     */
    public function buildValidator(EventInterface $event, Validator $validator, string $name)
    {
        $validator
            ->notEmptyString('uuid')
            ->add(
                'uuid',
                'valid',
                [
                    'rule' => 'uuid',
                    'message' => 'The UUID is not valid',
                ]
            )
            ->add(
                'uuid',
                'unique',
                [
                    'rule' => 'validateUnique',
                    'provider' => 'table',
                    'message' => 'The UUID name must be unique.',
                ]
            );

        return $validator;
    }
}
