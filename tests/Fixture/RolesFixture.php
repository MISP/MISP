<?php

declare(strict_types=1);

namespace App\Test\Fixture;

use Cake\TestSuite\Fixture\TestFixture;

class RolesFixture extends TestFixture
{
    public $connection = 'test';

    public const ROLE_ADMIN_ID = 1;
    public const ROLE_ORG_ADMIN_ID = 2;
    public const ROLE_REGULAR_USER_ID = 3;
    public const ROLE_PUBLISHER_ID = 4;
    public const ROLE_SYNC_ID = 5;
    public const ROLE_READ_ONLY_ID = 6;

    public function init(): void
    {
        $now = date('Y-m-d H:i:s', time());
        $this->records = [
            [
                'id' => self::ROLE_ADMIN_ID,
                'name' => 'admin',
                'created' => $now,
                'modified' => $now,
                'perm_add' => 1,
                'perm_modify' => 1,
                'perm_modify_org' => 1,
                'perm_publish' => 1,
                'perm_delegate' => 1,
                'perm_sync' => 1,
                'perm_admin' => 1,
                'perm_audit' => 1,
                'perm_full' => 1,
                'perm_auth' => 1,
                'perm_site_admin' => 1,
                'perm_regexp_access' => 1,
                'perm_tagger' => 1,
                'perm_template' => 1,
                'perm_sharing_group' => 1,
                'perm_tag_editor' => 1,
                'perm_sighting' => 1,
                'perm_object_template' => 1,
                'default_role' => 0,
                'memory_limit' => '',
                'max_execution_time' => '',
                'restricted_to_site_admin' => 0,
                'perm_publish_zmq' => 1,
                'perm_publish_kafka' => 1,
                'perm_decaying' => 1,
                'enforce_rate_limit' => 0,
                'rate_limit_count' => 0,
                'perm_galaxy_editor' => 1,
                'perm_warninglist' => 0
            ],
            [
                'id' => self::ROLE_ORG_ADMIN_ID,
                'name' => 'Org Admin',
                'created' => $now,
                'modified' => $now,
                'perm_add' => 1,
                'perm_modify' => 1,
                'perm_modify_org' => 1,
                'perm_publish' => 1,
                'perm_delegate' => 1,
                'perm_sync' => 0,
                'perm_admin' => 1,
                'perm_audit' => 1,
                'perm_full' => 0,
                'perm_auth' => 1,
                'perm_site_admin' => 0,
                'perm_regexp_access' => 0,
                'perm_tagger' => 1,
                'perm_template' => 1,
                'perm_sharing_group' => 1,
                'perm_tag_editor' => 1,
                'perm_sighting' => 0,
                'perm_object_template' => 0,
                'default_role' => 0,
                'memory_limit' => '',
                'max_execution_time' => '',
                'restricted_to_site_admin' => 1,
                'perm_publish_zmq' => 1,
                'perm_publish_kafka' => 1,
                'perm_decaying' => 1,
                'enforce_rate_limit' => 0,
                'rate_limit_count' => 0,
                'perm_galaxy_editor' => 1,
                'perm_warninglist' => 0
            ],
            [
                'id' => self::ROLE_REGULAR_USER_ID,
                'name' => 'User',
                'created' => $now,
                'modified' => $now,
                'perm_add' => 1,
                'perm_modify' => 1,
                'perm_modify_org' => 1,
                'perm_publish' => 0,
                'perm_delegate' => 0,
                'perm_sync' => 0,
                'perm_admin' => 0,
                'perm_audit' => 1,
                'perm_full' => 0,
                'perm_auth' => 1,
                'perm_site_admin' => 0,
                'perm_regexp_access' => 0,
                'perm_tagger' => 1,
                'perm_template' => 0,
                'perm_sharing_group' => 0,
                'perm_tag_editor' => 0,
                'perm_sighting' => 1,
                'perm_object_template' => 0,
                'default_role' => 1,
                'memory_limit' => '',
                'max_execution_time' => '',
                'restricted_to_site_admin' => 0,
                'perm_publish_zmq' => 0,
                'perm_publish_kafka' => 0,
                'perm_decaying' => 1,
                'enforce_rate_limit' => 0,
                'rate_limit_count' => 0,
                'perm_galaxy_editor' => 0,
                'perm_warninglist' => 0
            ],
            [
                'id' => self::ROLE_PUBLISHER_ID,
                'name' => 'Publisher',
                'created' => $now,
                'modified' => $now,
                'perm_add' => 1,
                'perm_modify' => 1,
                'perm_modify_org' => 1,
                'perm_publish' => 1,
                'perm_delegate' => 1,
                'perm_sync' => 0,
                'perm_admin' => 0,
                'perm_audit' => 1,
                'perm_full' => 0,
                'perm_auth' => 1,
                'perm_site_admin' => 0,
                'perm_regexp_access' => 0,
                'perm_tagger' => 1,
                'perm_template' => 0,
                'perm_sharing_group' => 0,
                'perm_tag_editor' => 0,
                'perm_sighting' => 1,
                'perm_object_template' => 0,
                'default_role' => 0,
                'memory_limit' => '',
                'max_execution_time' => '',
                'restricted_to_site_admin' => 0,
                'perm_publish_zmq' => 1,
                'perm_publish_kafka' => 1,
                'perm_decaying' => 1,
                'enforce_rate_limit' => 0,
                'rate_limit_count' => 0,
                'perm_galaxy_editor' => 0,
                'perm_warninglist' => 0
            ],
            [
                'id' => self::ROLE_SYNC_ID,
                'name' => 'Sync user',
                'created' => $now,
                'modified' => $now,
                'perm_add' => 1,
                'perm_modify' => 1,
                'perm_modify_org' => 1,
                'perm_publish' => 1,
                'perm_delegate' => 1,
                'perm_sync' => 1,
                'perm_admin' => 0,
                'perm_audit' => 1,
                'perm_full' => 0,
                'perm_auth' => 1,
                'perm_site_admin' => 0,
                'perm_regexp_access' => 0,
                'perm_tagger' => 1,
                'perm_template' => 0,
                'perm_sharing_group' => 1,
                'perm_tag_editor' => 1,
                'perm_sighting' => 1,
                'perm_object_template' => 0,
                'default_role' => 0,
                'memory_limit' => '',
                'max_execution_time' => '',
                'restricted_to_site_admin' => 0,
                'perm_publish_zmq' => 1,
                'perm_publish_kafka' => 1,
                'perm_decaying' => 1,
                'enforce_rate_limit' => 0,
                'rate_limit_count' => 0,
                'perm_galaxy_editor' => 1,
                'perm_warninglist' => 0
            ],
            [
                'id' => self::ROLE_READ_ONLY_ID,
                'name' => 'Read Only',
                'created' => $now,
                'modified' => $now,
                'perm_add' => 0,
                'perm_modify' => 0,
                'perm_modify_org' => 0,
                'perm_publish' => 0,
                'perm_delegate' => 0,
                'perm_sync' => 0,
                'perm_admin' => 0,
                'perm_audit' => 1,
                'perm_full' => 0,
                'perm_auth' => 1,
                'perm_site_admin' => 0,
                'perm_regexp_access' => 0,
                'perm_tagger' => 0,
                'perm_template' => 0,
                'perm_sharing_group' => 0,
                'perm_tag_editor' => 0,
                'perm_sighting' => 0,
                'perm_object_template' => 0,
                'default_role' => 0,
                'memory_limit' => '',
                'max_execution_time' => '',
                'restricted_to_site_admin' => 0,
                'perm_publish_zmq' => 0,
                'perm_publish_kafka' => 0,
                'perm_decaying' => 0,
                'enforce_rate_limit' => 0,
                'rate_limit_count' => 0,
                'perm_galaxy_editor' => 0,
                'perm_warninglist' => 0
            ]
        ];
        parent::init();
    }

    public function insert($db)
    {
        // hack to ignore duplicate entry errors since the roles table is previously populated by cake migrations
        try {
            parent::insert($db);
        } catch (\Exception $e) {
            if (str_contains($e->getMessage(), 'SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry')) {
                // ignore
            } else {
                throw $e;
            }
        }
    }
}
