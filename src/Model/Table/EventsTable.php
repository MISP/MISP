<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\Core\Configure;

class EventsTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('AuditLog');
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
}
