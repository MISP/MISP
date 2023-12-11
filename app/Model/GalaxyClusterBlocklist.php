<?php
App::uses('AppModel', 'Model');

class GalaxyClusterBlocklist extends AppModel
{
    public $useTable = 'galaxy_cluster_blocklists';

    public $recursive = -1;

    public $actsAs = array(
        'AuditLog',
        'SysLogLogable.SysLogLogable' => array( // TODO Audit, logable
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'full'
        ),
        'Containable',
    );

    public $blocklistFields = array('cluster_uuid', 'comment', 'cluster_info', 'cluster_orgc');
    public $blocklistTarget = 'cluster';

    public $validate = array(
        'cluster_uuid' => array(
            'unique' => array(
                'rule' => 'isUnique',
                'message' => 'Galaxy Cluster already blocklisted.'
            ),
            'uuid' => array(
                'rule' => array('uuid'),
                'message' => 'Please provide a valid UUID'
            ),
        )
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        if (empty($this->data['GalaxyClusterBlocklist']['id'])) {
            $this->data['GalaxyClusterBlocklist']['date_created'] = date('Y-m-d H:i:s');
        }
        if (empty($this->data['GalaxyClusterBlocklist']['comment'])) {
            $this->data['GalaxyClusterBlocklist']['comment'] = '';
        }
        return true;
    }

    /**
     * @param string $clusterUUID
     * @return bool
     */
    public function checkIfBlocked($clusterUUID)
    {
        return $this->hasAny([
            'cluster_uuid' => $clusterUUID,
        ]);
    }
}
