<?php
declare(strict_types=1);

namespace App\Model\Table;

use ArrayObject;
use Cake\Datasource\EntityInterface;
use Cake\Event\EventInterface;
use Cake\Validation\Validation;
use Cake\Validation\Validator;

class OrganisationsTable extends AppTable
{
    private $__orgCache = [];

    /**
     * Initialize method.
     *
     * @param array $config The configuration for the table.
     * @return void
     */
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

    /**
     * Callback method called before saving an entity.
     *
     * @param \Cake\Event\EventInterface $event The event instance.
     * @param \Cake\Datasource\EntityInterface $entity The entity being saved.
     * @param \ArrayObject $options The options passed to the save method.
     * @return void
     */
    public function beforeSave(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        if ($entity->isNew()) {
            $entity->date_created = date('Y-m-d H:i:s');
        }
        $entity->date_modified = date('Y-m-d H:i:s');
        // $entity->created_by = $this->ACL->getUser();   // FIXME force the value in the model, see also https://github.com/usemuffin/footprint
    }

    /**
     * Default validation rules for the table.
     *
     * @param \Cake\Validation\Validator $validator The validator instance.
     * @return \Cake\Validation\Validator The updated validator instance.
     */
    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->notEmptyString('name')
            ->requirePresence(['name', 'uuid'], 'create')
            ->add(
                'name',
                [
                    'unique' => [
                        'rule' => 'validateUnique',
                        'provider' => 'table',
                        'message' => 'The organisation name must be unique.',
                    ],
                    'maxLength' => [
                        'rule' => ['maxLength', 255],
                        'message' => 'Name cannot be more than 255 chars.',
                    ],
                ]
            )
            ->add(
                'type',
                'maxLength',
                [
                    'rule' => ['maxLength', 255],
                    'message' => 'Type cannot be more than 255 chars.',
                ],
            )
            ->add(
                'nationality',
                'maxLength',
                [
                    'rule' => ['maxLength', 255],
                    'message' => 'Nationality cannot be more than 255 chars.',
                ],
            )
            ->add(
                'sector',
                'maxLength',
                [
                    'rule' => ['maxLength', 255],
                    'message' => 'Sector cannot be more than 255 chars.',
                ],
            );

        return $validator;
    }

    /**
     * Capture the organization.
     *
     * @param mixed $org The organization to capture.
     * @return int|null The captured organization ID, or null if capture failed.
     */
    public function captureOrg($org): ?int
    {
        if (!empty($org['uuid'])) {
            $existingOrg = $this->find()->where(
                [
                    'uuid' => $org['uuid'],
                ]
            )->first();
        } else {
            return null;
        }
        if (empty($existingOrg)) {
            /** @var \App\Model\Entity\Organisation $entityToSave */
            $entityToSave = $this->newEmptyEntity();
            $this->patchEntity(
                $entityToSave,
                $org,
                [
                    'accessibleFields' => $entityToSave->getAccessibleFieldForNew(),
                ]
            );
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

    /**
     * Fetches an organization by its ID.
     *
     * @param int $id The ID of the organization to fetch.
     * @return mixed
     */
    public function fetchOrg(int $id)
    {
        if (empty($id)) {
            return false;
        }
        $conditions = ['Organisations.id' => $id];
        if (Validation::uuid($id)) {
            $conditions = ['Organisations.uuid' => $id];
        } elseif (!is_numeric($id)) {
            $conditions = ['LOWER(Organisations.name)' => strtolower($id)];
        }
        $org = $this->find(
            'all',
            [
                'conditions' => $conditions,
                'recursive' => -1,
            ]
        )->disableHydration()->first();

        return empty($org) ? false : $org;
    }

    /**
     * Attach organisations to evnet
     * @param array $data
     * @param array $fields
     * @return array
     */
    public function attachOrgs($event, $fields)
    {
        $toFetch = [];
        if (!isset($this->__orgCache[$event['orgc_id']])) {
            $toFetch[] = $event['orgc_id'];
        }
        if (!isset($this->__orgCache[$event['org_id']]) && $event['org_id'] != $event['orgc_id']) {
            $toFetch[] = $event['org_id'];
        }
        if (!empty($toFetch)) {
            $orgs = $this->find(
                'all',
                [
                    'conditions' => ['id IN' => $toFetch],
                    'recursive' => -1,
                    'fields' => $fields,
                ]
            );
            foreach ($orgs as $org) {
                $this->__orgCache[$org['id']] = $org;
            }
        }
        $event['Orgc'] = $this->__orgCache[$event['orgc_id']];
        $event['Org'] = $this->__orgCache[$event['org_id']];
        return $event;
    }
}
