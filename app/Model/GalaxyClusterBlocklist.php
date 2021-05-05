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
        $date = date('Y-m-d H:i:s');
        if (empty($this->data['GalaxyClusterBlocklist']['id'])) {
            $this->data['GalaxyClusterBlocklist']['date_created'] = $date;
        }
        if (empty($this->data['GalaxyClusterBlocklist']['comment'])) {
            $this->data['GalaxyClusterBlocklist']['comment'] = '';
        }
        return true;
    }

    public function checkIfBlocked($clusterUUID)
    {
        $entry = $this->find('first', array('conditions' => array('cluster_uuid' => $clusterUUID)));
        if (!empty($entry)) {
            return true;
        }
        return false;
    }
}
