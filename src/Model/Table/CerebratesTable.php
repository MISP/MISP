<?php
declare(strict_types=1);

namespace App\Model\Table;

use Cake\Validation\Validator;

/**
 * Cerebrates Model
 *
 * @method \App\Model\Entity\Cerebrate newEmptyEntity()
 * @method \App\Model\Entity\Cerebrate newEntity(array $data, array $options = [])
 * @method \App\Model\Entity\Cerebrate[] newEntities(array $data, array $options = [])
 * @method \App\Model\Entity\Cerebrate get($primaryKey, $options = [])
 * @method \App\Model\Entity\Cerebrate findOrCreate($search, ?callable $callback = null, $options = [])
 * @method \App\Model\Entity\Cerebrate patchEntity(\Cake\Datasource\EntityInterface $entity, array $data, array $options = [])
 * @method \App\Model\Entity\Cerebrate[] patchEntities(iterable $entities, array $data, array $options = [])
 * @method \App\Model\Entity\Cerebrate|false save(\Cake\Datasource\EntityInterface $entity, $options = [])
 * @method \App\Model\Entity\Cerebrate saveOrFail(\Cake\Datasource\EntityInterface $entity, $options = [])
 * @method \App\Model\Entity\Cerebrate[]|\Cake\Datasource\ResultSetInterface|false saveMany(iterable $entities, $options = [])
 * @method \App\Model\Entity\Cerebrate[]|\Cake\Datasource\ResultSetInterface saveManyOrFail(iterable $entities, $options = [])
 * @method \App\Model\Entity\Cerebrate[]|\Cake\Datasource\ResultSetInterface|false deleteMany(iterable $entities, $options = [])
 * @method \App\Model\Entity\Cerebrate[]|\Cake\Datasource\ResultSetInterface deleteManyOrFail(iterable $entities, $options = [])
 */
class CerebratesTable extends AppTable
{
    /**
     * Initialize method
     *
     * @param array $config The configuration for the Table.
     * @return void
     */
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('UUID');
        $this->addBehavior('AuditLog');
        $this->addBehavior('EncryptedFields', ['fields' => ['authkey']]);

        $this->belongsTo(
            'Organisations',
            [
                'dependent' => false,
                'cascadeCallbacks' => false,
                'foreignKey' => 'org_id',
                'propertyName' => 'Organisation',
            ]
        );

        $this->setTable('cerebrates');
        $this->setDisplayField('name');
        $this->setPrimaryKey('id');
    }

    /**
     * Default validation rules.
     *
     * @param \Cake\Validation\Validator $validator Validator instance.
     * @return \Cake\Validation\Validator
     */
    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->scalar('name')
            ->maxLength('name', 191)
            ->requirePresence('name', 'create')
            ->notEmptyString('name');

        $validator
            ->scalar('url')
            ->maxLength('url', 255)
            ->requirePresence('url', 'create')
            ->notEmptyString('url')
            ->url('url');

        $validator
            ->requirePresence('authkey', 'create')
            ->notEmptyString('authkey');

        $validator
            ->boolean('open')
            ->allowEmptyString('open');

        $validator
            ->integer('org_id')
            ->requirePresence('org_id', 'create')
            ->notEmptyString('org_id');

        $validator
            ->boolean('pull_orgs')
            ->allowEmptyString('pull_orgs');

        $validator
            ->boolean('pull_sharing_groups')
            ->allowEmptyString('pull_sharing_groups');

        $validator
            ->boolean('self_signed')
            ->allowEmptyString('self_signed');

        $validator
            ->scalar('cert_file')
            ->maxLength('cert_file', 255)
            ->allowEmptyFile('cert_file');

        $validator
            ->scalar('client_cert_file')
            ->maxLength('client_cert_file', 255)
            ->allowEmptyFile('client_cert_file');

        $validator
            ->boolean('internal')
            ->notEmptyString('internal');

        $validator
            ->boolean('skip_proxy')
            ->notEmptyString('skip_proxy');

        $validator
            ->scalar('description')
            ->allowEmptyString('description');

        return $validator;
    }
}
