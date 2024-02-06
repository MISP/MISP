<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use ArrayObject;
use Cake\Core\Configure;
use Cake\Datasource\EntityInterface;
use Cake\Event\EventInterface;
use Cake\Utility\Text;

class EventsTable extends AppTable
{
    private $assetCache = [];

    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');

        $this->belongsTo(
            'User',
            [
                'className' => 'Users',
                'foreignKey' => 'user_id'
            ]
        );
        $this->belongsTo(
            'ThreatLevel',
            [
                'className' => 'ThreatLevels',
                'foreignKey' => 'threat_level_id'
            ]
        );
        $this->belongsTo(
            'Org',
            [
                'className' => 'Organisations',
                'foreignKey' => 'org_id'
            ]
        );
        $this->belongsTo(
            'Orgc',
            [
                'className' => 'Organisations',
                'foreignKey' => 'orgc_id'
            ]
        );
        $this->belongsTo(
            'SharingGroup',
            [
                'className' => 'SharingGroups',
                'foreignKey' => 'sharing_group_id'
            ]
        );

        $this->hasMany(
            'Attributes',
            [
                'dependent' => true,
                'propertyName' => 'Attribute'
            ]
        );
        $this->hasMany(
            'ShadowAttributes',
            [
                'dependent' => true,
                'propertyName' => 'ShadowAttribute'
            ]
        );
        $this->hasMany(
            'Objects',
            [
                'dependent' => true,
                'propertyName' => 'Object',
                'className' => 'MispObjects',
            ]
        );
        $this->hasMany(
            'EventTags',
            [
                'dependent' => true,
                'propertyName' => 'EventTag',
            ]
        );
        $this->hasMany(
            'Sightings',
            [
                'dependent' => true,
                'propertyName' => 'Sighting',
            ]
        );
        $this->hasMany(
            'EventReports',
            [
                'dependent' => true,
                'propertyName' => 'EventReport',
            ]
        );
        $this->hasMany(
            'CryptographicKeys',
            [
                'dependent' => true,
                'propertyName' => 'CryptographicKey',
                'foreignKey' => 'parent_id',
                'conditions' => [
                    'parent_type' => 'Events'
                ],
            ]
        );
        $this->setDisplayField('title');
    }

    public function beforeSave(EventInterface $event, EntityInterface $entity, ArrayObject $options)
    {
        if ($entity->uuid === null) {
            $entity->uuid = Text::uuid();
        }

        return true;
    }

    public function createEventConditions($user)
    {
        $conditions = [];
        if (!$user['Role']['perm_site_admin']) {
            $sgids = $this->SharingGroup->authorizedIds($user);
            $unpublishedPrivate = Configure::read('MISP.unpublishedprivate');
            $conditions['AND']['OR'] = [
                'Event.org_id' => $user['org_id'],
                [
                    'AND' => [
                        'Event.distribution >' => 0,
                        'Event.distribution <' => 4,
                        $unpublishedPrivate ? ['Event.published' => 1] : [],
                    ],
                ],
                [
                    'AND' => [
                        'Event.sharing_group_id' => $sgids,
                        'Event.distribution' => 4,
                        $unpublishedPrivate ? ['Event.published' => 1] : [],
                    ]
                ]
            ];
        }
        return $conditions;
    }

    public function __cacheSharingGroupData($user, $useCache = false)
    {
        if ($useCache && isset($this->assetCache['sharingGroupData'])) {
            return $this->assetCache['sharingGroupData'];
        } else {
            $sharingGroupDataTemp = $this->SharingGroup->fetchAllAuthorised($user, 'simplified');
            $sharingGroupData = [];
            foreach ($sharingGroupDataTemp as $v) {
                if (isset($v['Organisation'])) {
                    $v['SharingGroup']['Organisation'] = $v['Organisation'];
                }
                if (isset($v['SharingGroupOrg'])) {
                    $v['SharingGroup']['SharingGroupOrg'] = $v['SharingGroupOrg'];
                }
                if (isset($v['SharingGroupServer'])) {
                    $v['SharingGroup']['SharingGroupServer'] = $v['SharingGroupServer'];
                    foreach ($v['SharingGroup']['SharingGroupServer'] as &$sgs) {
                        if ($sgs['server_id'] == 0) {
                            $sgs['Server'] = [
                                'id' => '0',
                                'url' => $this->__getAnnounceBaseurl(),
                                'name' => $this->__getAnnounceBaseurl()
                            ];
                        }
                    }
                }
                $sharingGroupData[$v['SharingGroup']['id']] = $v['SharingGroup'];
            }
            if ($useCache) {
                $this->assetCache['sharingGroupData'] = $sharingGroupData;
            }
            return $sharingGroupData;
        }
    }

    /**
     * Low level function to add an Event based on an Event $data array.
     *
     * @param array $data
     * @param bool $fromXml
     * @param array $user
     * @param int $org_id
     * @param int|null $passAlong Server ID or null
     * @param bool $fromPull
     * @param int|null $jobId
     * @param int $created_id
     * @param array $validationErrors
     * @return bool|int|string True when new event was created, int when event with the same uuid already exists, string when validation errors
     * @throws Exception
     */
    public function _add(array &$data, $fromXml, array $user, $org_id = 0, $passAlong = null, $fromPull = false, $jobId = null, &$created_id = 0, &$validationErrors = [])
    {
        // TODO: [3.x-MIGRATION] implement when events controller is migrated see #9391
        $data['Event']['user_id'] = $user['id'];
        if ($fromPull) {
            $data['Event']['org_id'] = $org_id;
        } else {
            $data['Event']['org_id'] = $user['Organisation']['id'];
        }
        if (!isset($data['Event']['orgc_id']) && !isset($data['Event']['orgc'])) {
            $data['Event']['orgc_id'] = $data['Event']['org_id'];
        }

        $event = $this->newEntity($data['Event']);
        $this->saveOrFail($event);

        return true;
    }

    public function _edit(array &$data, array $user, $id = null, $jobId = null, $passAlong = null, $force = false, $fast_update = false)
    {
        // TODO: [3.x-MIGRATION] implement when events controller is migrated see #9391
        return true;
    }
}
