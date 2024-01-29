<?php
App::uses('AppModel', 'Model');

class AnalystData extends AppModel
{

    public $recursive = -1;

    public $actsAs = array(
            'Containable'
    );

    public $valid_targets = [
        'Attribute',
        'Event',
        'GalaxyCluster',
        'Galaxy',
        'Object',
        'Note',
        'Opinion',
        'Relationship',
        'Organisation',
        'SharingGroup'
    ];

    const NOTE = 0,
        OPINION = 1,
        RELATIONSHIP = 2;

    public $current_user = null;

    public function __construct($id = false, $table = null, $ds = null)
    {
        parent::__construct($id, $table, $ds);
        $this->bindModel([
            'belongsTo' => [
                'Organisation' => [
                    'className' => 'Organisation',
                    'foreignKey' => false,
                    'conditions' => [
                        sprintf('%s.orgc_uuid = Organisation.uuid', $this->alias)
                    ],
                ]
            ]
        ]);
    }

    public function afterFind($results, $primary = false)
    {
        parent::afterFind($results, $primary);
        foreach ($results as $i => $v) {
            $results[$i][$this->alias]['note_type'] = $this->current_type_id;
            $results[$i][$this->alias]['note_type_name'] = $this->current_type;
            if (!isset($v['Organisation'])) {
                $this->Organisation = ClassRegistry::init('Organisation');
                $results[$i][$this->alias]['Organisation'] = $this->Organisation->find('first', ['condition' => ['uuid' => $v[$this->alias]['orgc_uuid']]])['Organisation'];
            } else {
                $results[$i][$this->alias]['Organisation'] = $v['Organisation'];
            }
            unset($results[$i]['Organisation']);
            $results[$i][$this->alias] = $this->fetchChildNotesAndOpinions($results[$i][$this->alias]);
        }
        return $results;
    }

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        if (empty($this->id) && empty($this->data[$this->current_type]['uuid'])) {
            $this->data[$this->current_type]['uuid'] = CakeText::uuid();
        }
        if (empty($this->id)) {
            if (empty($this->data[$this->current_type]['orgc_uuid']) || empty($this->current_user['Role']['perm_sync'])) {
                $this->data[$this->current_type]['orgc_uuid'] = $this->current_user['Organisation']['uuid'];
            }
            $this->data[$this->current_type]['org_uuid'] = $this->current_user['Organisation']['uuid'];
            $this->data[$this->current_type]['authors'] = $this->current_user['email'];
        }
        return true;
    }

    public function deduceType(string $uuid)
    {
        foreach ($this->valid_targets as $valid_target) {
            $this->{$valid_target} = ClassRegistry::init($valid_target);
            $result = $this->$valid_target->find('first', [
                'conditions' => [$valid_target.'.uuid' => $uuid],
                'recursive' => -1
            ]);
            if (!empty($result)) {
                return $valid_target;
            }
        }
        throw new NotFoundException(__('Invalid UUID'));
    }

    public function fetchChildNotesAndOpinions(array $analystData): array
    {
        $this->Note = ClassRegistry::init('Note');
        $this->Opinion = ClassRegistry::init('Opinion');
        $paramsNote = [
            'recursive' => -1,
            'contain' => ['Organisation'],
            'conditions' => [
                'object_type' => $this->current_type,
                'object_uuid' => $analystData['uuid'],
            ]
        ];
        $paramsOpinion = [
            'recursive' => -1,
            'contain' => ['Organisation'],
            'conditions' => [
                'object_type' => $this->current_type,
                'object_uuid' => $analystData['uuid'],
            ]
        ];

        // recursively fetch and include nested notes and opinions
        $childNotes = array_map(function ($item) {
            $expandedNotes = $this->fetchChildNotesAndOpinions($item[$this->Note->current_type]);
            return $expandedNotes;
        }, $this->Note->find('all', $paramsNote));
        $childOpinions = array_map(function ($item) {
            $expandedNotes = $this->fetchChildNotesAndOpinions($item[$this->Opinion->current_type]);
            return $expandedNotes;
        }, $this->Opinion->find('all', $paramsOpinion));

        if (!empty($childNotes)) {
            $analystData[$this->Note->current_type] = $childNotes;
        }
        if (!empty($childOpinions)) {
            $analystData[$this->Opinion->current_type] = $childOpinions;
        }
        return $analystData;
    }

    public function getExistingRelationships()
    {
        $existingRelationships = $this->find('column', [
            'recursive' => -1,
            'fields' => ['relationship_type'],
            'unique' => true,
        ]);
        $this->ObjectRelationship = ClassRegistry::init('ObjectRelationship');
        $objectRelationships = $this->ObjectRelationship->find('column', [
            'recursive' => -1,
            'fields' => ['name'],
            'unique' => true,
        ]);
        return array_unique(array_merge($existingRelationships, $objectRelationships));
    }
}
