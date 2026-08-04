<?php

App::uses('AppModel', 'Model');

class ObjectRelationship extends AppModel
{

    private $ObjectReference;

    public $actsAs = array(
            'Containable',
            'SysLogLogable.SysLogLogable' => array(	// TODO Audit, logable
                'userModel' => 'User',
                'userKey' => 'user_id',
                'change' => 'full'),
    );

    public $validate = array(
        'name' => array(
            'unique' => array(
                'rule' => 'isUnique',
                'message' => 'A relationship with this name already exists.'
            ),
            'valueNotEmpty' => array(
                'rule' => array('valueNotEmpty'),
            ),
        ),
    );

    public function afterFind($results, $primary = false)
    {
        foreach ($results as $k => $result) {
            if (!empty($result['ObjectRelationship']['format'])) {
                $results[$k]['ObjectRelationship']['format'] = JsonTool::decode($result['ObjectRelationship']['format'], true);
            }
        }
        return $results;
    }

    public function beforeSave($options = [])
    {
        parent::beforeSave($options);
        if (!empty($this->data[$this->alias]['format']) && is_array($this->data[$this->alias]['format'])) {
            $this->data[$this->alias]['format'] = JsonTool::encode($this->data[$this->alias]['format']);
        }
        return true;
    }


    public function update()
    {
        $relationsFile = APP . 'files/misp-objects/relationships/definition.json';
        if (file_exists($relationsFile)) {
            $relations = FileAccessTool::readJsonFromFile($relationsFile, true);
            if (!isset($relations['version'])) {
                $relations['version'] = 1;
            }
            $this->deleteAll(array('version <' => $relations['version']));
            foreach ($relations['values'] as $relation) {
                $relation['format'] = json_encode($relation['format']);
                $relation['version'] = $relations['version'];
                $this->create();
                $this->save($relation);
            }
        }
        return true;
    }

    public function getUsage(): array
    {
        $this->ObjectReference = ClassRegistry::init('ObjectReference');
        $this->Tag = ClassRegistry::init('Tag');
        $this->Relationship = ClassRegistry::init('Relationship');
        $objectCount = $this->ObjectReference->countForObject();
        $tagCount = $this->Tag->countRelationships();
        $analystRelationshipCount = $this->Relationship->countRelationships();
        return [
            'object_reference' => $objectCount,
            'tag_relationship' => $tagCount['all'],
            'analyst_relationship' => $analystRelationshipCount,
            'total' => $objectCount + $tagCount['all'] + $analystRelationshipCount,
        ];
    }
}
