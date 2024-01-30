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

    /** @var object|null */
    protected $Note;
    /** @var object|null */
    protected $Opinion;
    /** @var object|null */
    protected $ObjectRelationship;
    /** @var object|null */
    protected $User;
    /** @var object|null */
    public $Organisation;
    /** @var object|null */
    public $SharingGroup;

    public $current_user = null;

    public $belongsTo = [
        'SharingGroup' => [
            'className' => 'SharingGroup',
            'foreignKey' => 'sharing_group_id'
        ]
    ];

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
                ],
                'SharingGroup' => [
                    'className' => 'SharingGroup',
                    'foreignKey' => false,
                    'conditions' => [
                        sprintf('%s.sharing_group_id = SharingGroup.id', $this->alias)
                    ],
                ],
            ]
        ]);
    }

    public function afterFind($results, $primary = false)
    {
        parent::afterFind($results, $primary);

        $this->setUser();

        foreach ($results as $i => $v) {
            $results[$i][$this->alias]['note_type'] = $this->current_type_id;
            $results[$i][$this->alias]['note_type_name'] = $this->current_type;

            $results[$i] = $this->rearrangeOrganisation($results[$i], $this->current_user);
            $results[$i] = $this->rearrangeSharingGroup($results[$i], $this->current_user);

            if (!empty($results[$i][$this->alias]['uuid'])) {
                $results[$i][$this->alias] = $this->fetchChildNotesAndOpinions($results[$i][$this->alias]);
            }
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

    protected function setUser()
    {
        if (empty($this->current_user)) {
            $user_id = Configure::read('CurrentUserId');
            $this->User = ClassRegistry::init('User');
            if ($user_id) {
                $this->current_user = $this->User->getAuthUser($user_id);
            }
        }
    }

    private function rearrangeOrganisation(array $analystData): array
    {
        if (!empty($analystData[$this->alias]['orgc_uuid'])) {
            if (!isset($analystData['Organisation'])) {
                $this->Organisation = ClassRegistry::init('Organisation');
                $analystData[$this->alias]['Organisation'] = $this->Organisation->find('first', ['condition' => ['uuid' => $analystData[$this->alias]['orgc_uuid']]])['Organisation'];
            } else {
                $analystData[$this->alias]['Organisation'] = $analystData['Organisation'];
            }
            unset($analystData['Organisation']);
        }
        return $analystData;
    }

    private function rearrangeSharingGroup(array $analystData, array $user): array
    {
        if (isset($analystData[$this->alias]['distribution'])) {
            if ($analystData[$this->alias]['distribution'] == 4) {
                if (!isset($analystData['SharingGroup'])) {
                    $this->SharingGroup = ClassRegistry::init('SharingGroup');
                    $sg = $this->SharingGroup->fetchSG($analystData[$this->alias]['sharing_group_id'], $user, true);
                    $analystData[$this->alias]['SharingGroup'] = $sg['SharingGroup'];
                } else {
                    $analystData[$this->alias]['SharingGroup'] = $analystData['SharingGroup'];
                }
            } else {
                unset($analystData['SharingGroup']);
            }
        }
        return $analystData;
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
