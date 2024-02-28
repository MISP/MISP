<?php

namespace App\Model\Table;

use App\Lib\Tools\ServerSyncTool;
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
     * @param array $user
     * @param ServerSyncTool $serverSync
     * @return int
     * @throws HttpSocketHttpException
     * @throws HttpSocketJsonException
     */
    public function pullProposals(array $user, ServerSyncTool $serverSync)
    {
        // TODO: [3.x-MIGRATION] Implement pullProposals() method.

        return 0;
    }
}
