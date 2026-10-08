<?php
/**
 * For AttributeValueHydratorDbTest, required once the application is booted.
 * Not a test file.
 */

/**
 * Reads objects with their attributes, and runs a find of its own while the
 * outer find still holds the attribute rows.
 */
class HydratorNestedFindObject extends AppModel
{
    public $useTable = 'objects';

    public $recursive = 1;

    public $hasMany = [
        'Attribute' => [
            'className' => 'MispAttribute',
            'foreignKey' => 'object_id',
        ],
    ];

    /** @var array|null What the inner find returned */
    public $innerResult;

    public function afterFind($results, $primary = false)
    {
        $this->innerResult = ClassRegistry::init('MispObject')->find('first', [
            'conditions' => ['Object.id' => $results[0]['NestedObject']['id']],
            'contain' => ['Attribute'],
        ]);
        return $results;
    }
}
