<?php
App::uses('AppModel', 'Model');
App::uses('ConnectionManager', 'Model');
App::uses('Sanitize', 'Utility');

class SightingdbOrg extends AppModel
{
    public $belongsTo = array(
        'Sightingdb' => array(
            'className' => 'Sightingdb',
            'foreignKey' => 'sightingdb_id'
        ),
        'Organisation' => array(
            'className' => 'Organisation',
            'foreignKey' => 'org_id'
        )
    );

    public $actsAs = array(
        'AuditLog',
        'SysLogLogable.SysLogLogable' => array(
            'userModel' => 'User',
            'userKey' => 'user_id',
            'change' => 'full'),
        'Trim',
        'Containable',
    );

    public function resetOrgs($sightingdbId, $org_ids)
    {
        $sightingdb = $this->Sightingdb->find('first', array(
            'conditions' => array('Sightingdb.id' => $sightingdbId),
            'recursive' => -1
        ));
        if (empty($sightingdb)) {
            return false;
        }
        $this->deleteAll(array('SightingdbOrg.sightingdb_id' => $sightingdbId));
        if (!empty($org_ids)) {
            if (!is_array($org_ids)) {
                $org_ids = explode(',', $org_ids);
            }
            foreach ($org_ids as $org_id) {
                debug($org_id);
                $this->create();
                $this->save(
                    array(
                        'SightingdbOrg' => array(
                            'sightingdb_id' => $sightingdbId,
                            'org_id' => $org_id
                        )
                    )
                );
            }
        }
        return true;
    }
}
