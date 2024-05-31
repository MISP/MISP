<?php

namespace App\Model\Table;

use App\Lib\Tools\ServerSyncTool;
use App\Model\Entity\User;
use App\Model\Table\AppTable;

class ShadowAttributesTable extends AppTable
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->belongsTo(
            'Events',
            [
                'propertyName' => 'Event'
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
            'EventOrg',
            [
                'className' => 'Organisations',
                'foreignKey' => 'event_org_id'
            ]
        );
        $this->belongsTo(
            'Attribute',
            [
                'className' => 'Attributes',
                'foreignKey' => 'old_id'
            ]
        );
    }

    /**
     * @param User $user
     * @param ServerSyncTool $serverSync
     * @return int
     * @throws HttpSocketHttpException
     * @throws HttpSocketJsonException
     */
    public function pullProposals(User $user, ServerSyncTool $serverSync)
    {
        // TODO: [3.x-MIGRATION] Implement pullProposals() method.

        return 0;
    }

    /**
     * @param int $eventId
     * @return array Key is organisation ID, value is an organisation name
     */
    public function getEventContributors($eventId)
    {
        $orgIds = $this->find(
            'column',
            [
                'fields' => ['ShadowAttributes.org_id'],
                'conditions' => ['event_id IN' => $eventId],
                'unique' => true,
                'order' => false
            ]
        );
        if (empty($orgIds)) {
            return [];
        }

        $OrganisationsTable = $this->fetchTable('Organisations');
        return $OrganisationsTable->find(
            'list',
            [
                'recursive' => -1,
                'fields' => ['id', 'name'],
                'conditions' => ['id IN' => $orgIds]
            ]
        )->toArray();
    }
}
