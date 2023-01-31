<?php

namespace App\Model\Table;

use App\Model\Table\AppTable;
use Cake\ORM\Table;
use Cake\Validation\Validator;

class RolesTable extends AppTable
{
    const PERMISSION_CONSTANTS = [
        'read_only' => 0,
        'manage_own' => 1,
        'manage_org' => 2,
        'publish' => 3
    ];

    public $premissionLevelName = [
        'Read Only',
        'Manage Own Events',
        'Manage Organisation Events',
        'Manage and Publish Organisation Events'
    ];


    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->addBehavior('UUID');
        $this->addBehavior('AuditLog');
        $this->hasMany(
            'Users',
            [
                'dependent' => false,
                'cascadeCallbacks' => false
            ]
        );
        $this->setDisplayField('name');
    }

    public function validationDefault(Validator $validator): Validator
    {
        $validator
            ->notEmptyString('name')
            ->requirePresence(['name'], 'create');
        return $validator;
    }

       /**
     * @return array[]
     */
    public function permFlags()
    {
        return array(
            'perm_site_admin' => array(
                'id' => 'RolePermSiteAdmin',
                'text' => 'Site Admin',
                'readonlyenabled' => false,
                'title' => __('Unrestricted access to any data and functionality on this instance.')
            ),
            'perm_admin' => array(
                'id' => 'RolePermAdmin',
                'text' => 'Org Admin',
                'readonlyenabled' => false,
                'title' => __('Limited organisation admin - create, manage users of their own organisation.')
            ),
            'perm_sync' => array(
                'id' => 'RolePermSync',
                'text' => 'Sync Actions',
                'readonlyenabled' => true,
                'title' => __('Synchronisation permission, can be used to connect two MISP instances create data on behalf of other users. Make sure that the role with this permission has also access to tagging and tag editing rights.')
            ),
            'perm_audit' => array(
                'id' => 'RolePermAudit',
                'text' => 'Audit Actions',
                'readonlyenabled' => true,
                'title' => __('Access to the audit logs of the user\'s organisation.')
            ),
            'perm_auth' => array(
                'id' => 'RolePermAuth',
                'text' => 'Auth key access',
                'readonlyenabled' => true,
                'title' => __('Users with this permission have access to authenticating via their Auth keys, granting them access to the API.'),
                'site_admin_optional' => true
            ),
            'perm_regexp_access' => array(
                'id' => 'RolePermRegexpAccess',
                'text' => 'Regex Actions',
                'readonlyenabled' => false,
                'title' => __('Users with this role can modify the regex rules affecting how data is fed into MISP. Make sure that caution is advised with handing out roles that include this permission, user controlled executed regexes are dangerous.')
            ),
            'perm_tagger' => array(
                'id' => 'RolePermTagger',
                'text' => 'Tagger',
                'readonlyenabled' => false,
                'title' => __('Users with roles that include this permission can attach or detach existing tags to and from events/attributes.')
            ),
            'perm_tag_editor' => array(
                'id' => 'RolePermTagEditor',
                'text' => 'Tag Editor',
                'readonlyenabled' => false,
                'title' => __('This permission gives users the ability to create tags.')
            ),
            'perm_template' => array(
                'id' => 'RolePermTemplate',
                'text' => 'Template Editor',
                'readonlyenabled' => false,
                'title' => __('Create or modify templates, to be used when populating events.')
            ),
            'perm_sharing_group' => array(
                'id' => 'RolePermSharingGroup',
                'text' => 'Sharing Group Editor',
                'readonlyenabled' => false,
                'title' => __('Permission to create or modify sharing groups.')
            ),
            'perm_delegate' => array(
                'id' => 'RolePermDelegate',
                'text' => 'Delegations Access',
                'readonlyenabled' => false,
                'title' => __('Allow users to create delegation requests for their own org only events to trusted third parties.')
            ),
            'perm_sighting' => array(
                'id' => 'RolePermSighting',
                'text' => 'Sighting Creator',
                'readonlyenabled' => true,
                'title' => __('Permits the user to push feedback on attributes into MISP by providing sightings.')
            ),
            'perm_object_template' => array(
                'id' => 'RolePermObjectTemplate',
                'text' => 'Object Template Editor',
                'readonlyenabled' => false,
                'title' => __('Create or modify MISP Object templates.')
            ),
            'perm_galaxy_editor' => array(
                'id' => 'RolePermGalaxyEditor',
                'text' => 'Galaxy Editor',
                'readonlyenabled' => false,
                'title' => __('Create or modify MISP Galaxies and MISP Galaxies Clusters.')
            ),
            'perm_decaying' => array(
                'id' => 'RolePermDecaying',
                'text' => 'Decaying Model Editor',
                'readonlyenabled' => true,
                'title' => __('Create or modify MISP Decaying Models.')
            ),
            'perm_publish_zmq' => array(
                'id' => 'RolePermPublishZmq',
                'text' => 'ZMQ publisher',
                'readonlyenabled' => false,
                'title' => __('Allow users to publish data to the ZMQ pubsub channel via the publish event to ZMQ button.')
            ),
            'perm_publish_kafka' => array(
                'id' => 'RolePermPublishKafka',
                'text' => 'Kafka publisher',
                'readonlyenabled' => false,
                'title' => __('Allow users to publish data to Kafka via the publish event to Kafka button.'),
            ),
            'perm_warninglist' => array(
                'id' => 'RolePermWarninglist',
                'text' => 'Warninglist Editor',
                'readonlyenabled' => false,
                'title' => __('Allow to manage warninglists.'),
            )
        );
    }
}
