<?php

App::uses('AppModel', 'Model');

class ObjectRelationship extends AppModel
{
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
}
