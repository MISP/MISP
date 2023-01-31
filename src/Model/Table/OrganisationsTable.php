<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\ORM\Table;
use Cake\Validation\Validator;
use Cake\Error\Debugger;
use Cake\Event\EventInterface;
use Cake\Datasource\EntityInterface;
use ArrayObject;

class OrganisationsTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('UUID');
        //$this->addBehavior('Timestamp');
        $this->addBehavior('AuditLog');
        /*$this->addBehavior('NotifyAdmins', [
            'fields' => ['uuid', 'name', 'url', 'nationality', 'sector', 'type', 'contacts', 'modified', 'meta_fields'],
        ]);*/
        $this->setDisplayField('name');
    }

    public function beforeSave(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        if ($entity->isNew()) {
            $entity->date_created = date('Y-m-d H:i:s');
        }
        $entity->date_modified = date('Y-m-d H:i:s');
        return;
    }

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->notEmptyString('name')
            ->notEmptyString('uuid')
            ->requirePresence(['name', 'uuid'], 'create');
        return $validator;
    }

    public function captureOrg($org): ?int
    {
        if (!empty($org['uuid'])) {
            $existingOrg = $this->find()->where([
                'uuid' => $org['uuid']
            ])->first();
        } else {
            return null;
        }
        if (empty($existingOrg)) {
            $entityToSave = $this->newEmptyEntity();
            $this->patchEntity($entityToSave, $org, [
                'accessibleFields' => $entityToSave->getAccessibleFieldForNew()
            ]);
        } else {
            $this->patchEntity($existingOrg, $org);
            $entityToSave = $existingOrg;
        }
        $entityToSave->setDirty('modified', false);
        $savedEntity = $this->save($entityToSave, ['associated' => false]);
        if (!$savedEntity) {
            return null;
        }
        return $savedEntity->id;
    }
}
