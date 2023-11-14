<?php

namespace App\Model\Entity;

use App\Model\Entity\AppModel;
use Cake\ORM\TableRegistry;

class Organisation extends AppModel
{
    protected $_accessible = [
        '*' => true,
        'id' => false,
        'date_created' => false
    ];

    protected $_accessibleOnNew = [
        'date_created' => true
    ];

    public const ORGANISATION_ASSOCIATIONS = [
        'Correlation' => ['table' => 'correlations', 'fields' => ['org_id']],
        'Event' => ['table' => 'events', 'fields' => ['org_id', 'orgc_id']],
        'Job' => ['table' => 'jobs', 'fields' => ['org_id']],
        'Server' => ['table' => 'servers', 'fields' => ['org_id', 'remote_org_id']],
        'ShadowAttribute' => ['table' => 'shadow_attributes', 'fields' => ['org_id', 'event_org_id']],
        'SharingGroup' => ['table' => 'sharing_groups', 'fields' => ['org_id']],
        'SharingGroupOrg' => ['table' => 'sharing_group_orgs', 'fields' => ['org_id']],
        'Thread' => ['table' => 'threads', 'fields' => ['org_id']],
        'User' => ['table' => 'users', 'fields' => ['org_id']]
    ];

    public const GENERIC_MISP_ORGANISATION = [
        'id' => '0',
        'name' => 'MISP',
        'date_created' => '',
        'date_modified' => '',
        'description' => 'Automatically generated MISP organisation',
        'type' => '',
        'nationality' => 'Not specified',
        'sector' => '',
        'created_by' => '0',
        'uuid' => '0',
        'contacts' => '',
        'local' => true,
        'restricted_to_domain' => [],
        'landingpage' => null
    ];

    protected function _getUserCount()
    {
        $users = TableRegistry::getTableLocator()->get('Users');
        $user_count = $users->find('all')->where(['org_id' => $this->id])->count();
        return $user_count;
    }

    public function rearrangeForAPI(): void
    {
    }
}
