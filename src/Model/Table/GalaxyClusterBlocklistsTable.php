<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use ArrayObject;
use Cake\Event\EventInterface;

class GalaxyClusterBlocklistsTable extends AppTable
{
    public $useTable = 'galaxy_cluster_blocklists';

    public $recursive = -1;

    public $actsAs = [
        'AuditLog',
        'SysLogLogable.SysLogLogable' => [ // TODO Audit, logable
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'full'
        ],
        'Containable',
    ];

    public $blocklistFields = ['cluster_uuid', 'comment', 'cluster_info', 'cluster_orgc'];
    public $blocklistTarget = 'cluster';

    public $validate = [
        'cluster_uuid' => [
            'unique' => [
                'rule' => 'isUnique',
                'message' => 'Galaxy Cluster already blocklisted.'
            ],
            'uuid' => [
                'rule' => ['uuid'],
                'message' => 'Please provide a valid UUID'
            ],
        ]
    ];

    public function beforeMarshal(EventInterface $event, ArrayObject $data, ArrayObject $options)
    {
        if (empty($data['id'])) {
            $data['date_created'] = date('Y-m-d H:i:s');
        }
        if (empty($data['comment'])) {
            $data['comment'] = '';
        }
    }

    /**
     * @param string $clusterUUID
     * @return bool
     */
    public function checkIfBlocked($clusterUUID)
    {
        return $this->exists(
            [
                'cluster_uuid' => $clusterUUID,
            ]
        );
    }
}
