<?php
/**
 * Application model for Cake.
 *
 * This file is application-wide model file. You can put all
 * application-wide model-related methods here.
 *
 * PHP 5
 *
 * CakePHP(tm) : Rapid Development Framework (http://cakephp.org)
 * Copyright 2005-2012, Cake Software Foundation, Inc. (http://cakefoundation.org)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright 2005-2012, Cake Software Foundation, Inc. (http://cakefoundation.org)
 * @link          http://cakephp.org CakePHP(tm) Project
 * @package       app.Model
 * @since         CakePHP(tm) v 0.2.9
 * @license       MIT License (http://www.opensource.org/licenses/mit-license.php)
 */

App::uses('Model', 'Model');
App::uses('LogableBehavior', 'Assets.models/behaviors');
App::uses('BlowfishPasswordHasher', 'Controller/Component/Auth');
class AppModel extends Model
{
    public $name;

    public $loadedPubSubTool = false;

    public $start = 0;

    public $inserted_ids = array();

    private $__redisConnection = false;

    private $__profiler = array();

    public $elasticSearchClient = false;
    public $s3Client = false;

    public function __construct($id = false, $table = null, $ds = null)
    {
        parent::__construct($id, $table, $ds);

        $this->name = get_class($this);
    }

    // deprecated, use $db_changes
    // major -> minor -> hotfix -> requires_logout
    public $old_db_changes = array(
        2 => array(
            4 => array(
                18 => false, 19 => false, 20 => false, 25 => false, 27 => false,
                32 => false, 33 => true, 38 => true, 39 => true, 40 => false,
                42 => false, 44 => false, 45 => false, 49 => true, 50 => false,
                51 => false, 52 => false, 55 => true, 56 => true, 57 => true,
                58 => false, 59 => false, 60 => false, 61 => false, 62 => false,
                63 => false, 64 => false, 65 => false, 66 => false, 67 => true,
                68 => false, 69 => false, 71 => false, 72 => false, 73 => false,
                75 => false, 77 => false, 78 => false, 79 => false, 80 => false,
                81 => false, 82 => false, 83 => false, 84 => false, 85 => false,
                86 => false, 87 => false
            )
        )
    );

    public $db_changes = array(
        1 => false, 2 => false, 3 => false, 4 => true, 5 => false, 6 => false,
        7 => false, 8 => false, 9 => false, 10 => false, 11 => false, 12 => false,
        13 => false, 14 => false, 15 => false, 18 => false, 19 => false, 20 => false,
        21 => false, 22 => false
    );

    public function afterSave($created, $options = array())
    {
        if ($created) {
            $this->inserted_ids[] = $this->getInsertID();
        }
        return true;
    }

    // Generic update script
    // add special cases where the upgrade does more than just update the DB
    // this could become useful in the future
    public function updateMISP($command)
    {
        switch ($command) {
            case '2.4.20':
                $this->updateDatabase($command);
                $this->ShadowAttribute = ClassRegistry::init('ShadowAttribute');
                $this->ShadowAttribute->upgradeToProposalCorrelation();
                break;
            case '2.4.25':
                $this->updateDatabase($command);
                $newFeeds = array(
                    array('provider' => 'CIRCL', 'name' => 'CIRCL OSINT Feed', 'url' => 'https://www.circl.lu/doc/misp/feed-osint', 'enabled' => 0),
                );
                $this->__addNewFeeds($newFeeds);
                break;
            case '2.4.27':
                $newFeeds = array(
                    array('provider' => 'Botvrij.eu', 'name' => 'The Botvrij.eu Data','url' => 'http://www.botvrij.eu/data/feed-osint', 'enabled' => 0)
                );
                $this->__addNewFeeds($newFeeds);
                break;
            case '2.4.49':
                $this->updateDatabase($command);
                $this->SharingGroup = ClassRegistry::init('SharingGroup');
                $this->SharingGroup->correctSyncedSharingGroups();
                $this->SharingGroup->updateRoaming();
                break;
            case '2.4.55':
                $this->updateDatabase('addSightings');
                break;
            case '2.4.66':
                $this->updateDatabase('2.4.66');
                $this->cleanCacheFiles();
                $this->Sighting = Classregistry::init('Sighting');
                $this->Sighting->addUuids();
                break;
            case '2.4.67':
                $this->updateDatabase('2.4.67');
                $this->Sighting = Classregistry::init('Sighting');
                $this->Sighting->addUuids();
                $this->Sighting->deleteAll(array('NOT' => array('Sighting.type' => array(0, 1, 2))));
                break;
            case '2.4.71':
                $this->OrgBlacklist = Classregistry::init('OrgBlacklist');
                $values = array(
                    array('org_uuid' => '58d38339-7b24-4386-b4b4-4c0f950d210f', 'org_name' => 'Setec Astrononomy', 'comment' => 'default example'),
                    array('org_uuid' => '58d38326-eda8-443a-9fa8-4e12950d210f', 'org_name' => 'Acme Finance', 'comment' => 'default example')
                );
                foreach ($values as $value) {
                    $found = $this->OrgBlacklist->find('first', array('conditions' => array('org_uuid' => $value['org_uuid']), 'recursive' => -1));
                    if (empty($found)) {
                        $this->OrgBlacklist->create();
                        $this->OrgBlacklist->save($value);
                    }
                }
                $this->updateDatabase($command);
                break;
            case '2.4.86':
                $this->MispObject = Classregistry::init('MispObject');
                $this->MispObject->removeOrphanedObjects();
                $this->updateDatabase($command);
                break;
            case 5:
                $this->updateDatabase($command);
                $this->Feed = Classregistry::init('Feed');
                $this->Feed->setEnableFeedCachingDefaults();
                break;
            case 8:
                $this->Server = Classregistry::init('Server');
                $this->Server->restartWorkers();
                break;
            case 10:
                $this->updateDatabase($command);
                $this->Role = Classregistry::init('Role');
                $this->Role->setPublishZmq();
                break;
            case 12:
                $this->__forceSettings();
                break;
            default:
                $this->updateDatabase($command);
                break;
        }
    }

    private function __addNewFeeds($feeds)
    {
        $this->Feed = ClassRegistry::init('Feed');
        $this->Log = ClassRegistry::init('Log');
        $feedNames = array();
        foreach ($feeds as $feed) {
            $feedNames[] = $feed['name'];
        }
        $feedNames = implode(', ', $feedNames);
        $result = $this->Feed->addDefaultFeeds($feeds);
        $this->Log->create();
        $entry = array(
                'org' => 'SYSTEM',
                'model' => 'Server',
                'model_id' => 0,
                'email' => 'SYSTEM',
                'action' => 'update_database',
                'user_id' => 0,
                'title' => 'Added new default feeds.'
        );
        if ($result) {
            $entry['change'] = 'Feeds added: ' . $feedNames;
        } else {
            $entry['change'] = 'Tried adding new feeds but something went wrong.';
        }
        $this->Log->save($entry);
    }

    // SQL scripts for updates
    public function updateDatabase($command)
    {
        $dataSourceConfig = ConnectionManager::getDataSource('default')->config;
        $dataSource = $dataSourceConfig['datasource'];
        $sqlArray = array();
        $indexArray = array();
        $this->Log = ClassRegistry::init('Log');
        $clean = true;
        switch ($command) {
            case 'extendServerOrganizationLength':
                $sqlArray[] = 'ALTER TABLE `servers` MODIFY COLUMN `organization` varchar(255) NOT NULL;';
                break;
            case 'convertLogFieldsToText':
                $sqlArray[] = 'ALTER TABLE `logs` MODIFY COLUMN `title` text, MODIFY COLUMN `change` text;';
                break;
            case 'addEventBlacklists':
                $sqlArray[] = 'CREATE TABLE IF NOT EXISTS `event_blacklists` ( `id` int(11) NOT NULL AUTO_INCREMENT, `event_uuid` varchar(40) COLLATE utf8_bin NOT NULL, `created` datetime NOT NULL, PRIMARY KEY (`id`), `event_info` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL, `comment` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL, `event_orgc` VARCHAR( 255 ) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;';
                break;
            case 'addOrgBlacklists':
                $sqlArray[] = 'CREATE TABLE IF NOT EXISTS `org_blacklists` ( `id` int(11) NOT NULL AUTO_INCREMENT, `org_uuid` varchar(40) COLLATE utf8_bin NOT NULL, `created` datetime NOT NULL, PRIMARY KEY (`id`), `org_name` varchar(255) COLLATE utf8_bin NOT NULL, `comment` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;';
                break;
            case 'addEventBlacklistsContext':
                $sqlArray[] = 'ALTER TABLE  `event_blacklists` ADD  `event_orgc` VARCHAR( 255 ) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL , ADD  `event_info` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL, ADD `comment` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL;';
                break;
            case 'addSightings':
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS sightings (
				id int(11) NOT NULL AUTO_INCREMENT,
				attribute_id int(11) NOT NULL,
				event_id int(11) NOT NULL,
				org_id int(11) NOT NULL,
				date_sighting bigint(20) NOT NULL,
				PRIMARY KEY (id),
				INDEX attribute_id (attribute_id),
				INDEX event_id (event_id),
				INDEX org_id (org_id)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;";
                break;
            case 'makeAttributeUUIDsUnique':
                $this->__dropIndex('attributes', 'uuid');
                $sqlArray[] = 'ALTER TABLE `attributes` ADD UNIQUE (uuid);';
                break;
            case 'makeEventUUIDsUnique':
                $this->__dropIndex('events', 'uuid');
                $sqlArray[] = 'ALTER TABLE `events` ADD UNIQUE (uuid);';
                break;
            case 'cleanSessionTable':
                $sqlArray[] = 'DELETE FROM cake_sessions WHERE expires < ' . time() . ';';
                $clean = false;
                break;
            case 'destroyAllSessions':
                $sqlArray[] = 'DELETE FROM cake_sessions;';
                $clean = false;
                break;
            case 'addIPLogging':
                $sqlArray[] = 'ALTER TABLE `logs` ADD  `ip` varchar(45) COLLATE utf8_bin DEFAULT NULL;';
                break;
            case 'addCustomAuth':
                $sqlArray[] = "ALTER TABLE `users` ADD `external_auth_required` tinyint(1) NOT NULL DEFAULT 0;";
                $sqlArray[] = 'ALTER TABLE `users` ADD `external_auth_key` text COLLATE utf8_bin;';
                break;
            case '24betaupdates':
                $sqlArray = array();
                $sqlArray[] = "ALTER TABLE `shadow_attributes` ADD  `proposal_to_delete` tinyint(1) NOT NULL DEFAULT 0;";

                $sqlArray[] = 'ALTER TABLE `logs` MODIFY  `change` text COLLATE utf8_bin NOT NULL;';

                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `taxonomies` (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`namespace` varchar(255) COLLATE utf8_bin NOT NULL,
					`description` text COLLATE utf8_bin NOT NULL,
					`version` int(11) NOT NULL,
					`enabled` tinyint(1) NOT NULL DEFAULT 0,
					PRIMARY KEY (`id`)
					) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;";

                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `taxonomy_entries` (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`taxonomy_predicate_id` int(11) NOT NULL,
					`value` text COLLATE utf8_bin NOT NULL,
					`expanded` text COLLATE utf8_bin NOT NULL,
					PRIMARY KEY (`id`),
					KEY `taxonomy_predicate_id` (`taxonomy_predicate_id`)
					) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;";

                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `taxonomy_predicates` (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`taxonomy_id` int(11) NOT NULL,
					`value` text COLLATE utf8_bin NOT NULL,
					`expanded` text COLLATE utf8_bin NOT NULL,
					PRIMARY KEY (`id`),
					KEY `taxonomy_id` (`taxonomy_id`)
					) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;";

                $sqlArray[] = 'ALTER TABLE `jobs` ADD  `org` text COLLATE utf8_bin NOT NULL;';

                $sqlArray[] = 'ALTER TABLE  `servers` ADD  `name` varchar(255) NOT NULL;';

                $sqlArray[] = 'ALTER TABLE  `sharing_groups` ADD  `sync_user_id` INT( 11 ) NOT NULL DEFAULT \'0\' AFTER `org_id`;';

                $sqlArray[] = 'ALTER TABLE `users` ADD  `disabled` BOOLEAN NOT NULL;';
                $sqlArray[] = 'ALTER TABLE `users` ADD  `expiration` datetime DEFAULT NULL;';

                $sqlArray[] = 'UPDATE `roles` SET `perm_template` = 1 WHERE `perm_site_admin` = 1 OR `perm_admin` = 1;';
                $sqlArray[] = 'UPDATE `roles` SET `perm_sharing_group` = 1 WHERE `perm_site_admin` = 1 OR `perm_sync` = 1;';

                //create indexes
                break;
            case 'indexTables':
                $fieldsToIndex = array(
                    'attributes' => array(array('value1', 'INDEX', '255'), array('value2', 'INDEX', '255'), array('event_id', 'INDEX'), array('sharing_group_id', 'INDEX'), array('uuid', 'INDEX')),
                    'correlations' =>  array(array('org_id', 'INDEX'), array('event_id', 'INDEX'), array('attribute_id', 'INDEX'), array('sharing_group_id', 'INDEX'), array('1_event_id', 'INDEX'), array('1_attribute_id', 'INDEX'), array('a_sharing_group_id', 'INDEX'), array('value', 'FULLTEXT')),
                    'events' => array(array('info', 'FULLTEXT'), array('sharing_group_id', 'INDEX'), array('org_id', 'INDEX'), array('orgc_id', 'INDEX'), array('uuid', 'INDEX')),
                    'event_tags' => array(array('event_id', 'INDEX'), array('tag_id', 'INDEX')),
                    'organisations' => array(array('uuid', 'INDEX'), array('name', 'FULLTEXT')),
                    'posts' => array(array('post_id', 'INDEX'), array('thread_id', 'INDEX')),
                    'shadow_attributes' => array(array('value1', 'INDEX', '255'), array('value2', 'INDEX', '255'), array('old_id', 'INDEX'), array('event_id', 'INDEX'), array('uuid', 'INDEX'), array('event_org_id', 'INDEX'), array('event_uuid', 'INDEX')),
                    'sharing_groups' => array(array('org_id', 'INDEX'), array('sync_user_id', 'INDEX'), array('uuid', 'INDEX'), array('organisation_uuid', 'INDEX')),
                    'sharing_group_orgs' => array(array('sharing_group_id', 'INDEX'), array('org_id', 'INDEX')),
                    'sharing_group_servers' => array(array('sharing_group_id', 'INDEX'), array('server_id', 'INDEX')),
                    'servers' => array(array('org_id', 'INDEX'), array('remote_org_id', 'INDEX')),
                    'tags' => array(array('name', 'FULLTEXT')),
                    'threads' => array(array('user_id', 'INDEX'), array('event_id', 'INDEX'), array('org_id', 'INDEX'), array('sharing_group_id', 'INDEX')),
                    'users' => array(array('org_id', 'INDEX'), array('server_id', 'INDEX'), array('email', 'INDEX')),
                );

                $version = $this->query('select version();');
                $version = $version[0][0]['version()'];
                $version = explode('.', $version);
                $version[0] = intval($version[0]);
                $version[1] = intval($version[1]);
                $downgrade = true;
                if ($version[0] > 5 || ($version[0] == 5 && $version[1] > 5)) {
                    $downgrade = false;
                }

                // keep the fulltext for now, we can change it later to actually use it once we require MySQL 5.6 / or if we decide to move some tables to MyISAM

                foreach ($fieldsToIndex as $table => $fields) {
                    $downgradeThis = false;
                    $table_data = $this->query("SHOW TABLE STATUS WHERE Name = '" . $table . "'");
                    if ($downgrade && $table_data[0]['TABLES']['Engine'] !== 'MyISAM') {
                        $downgradeThis = true;
                    }
                    foreach ($fields as $field) {
                        $extra = '';
                        $this->__dropIndex($table, $field[0]);
                        if (isset($field[2])) {
                            $extra = ' (' . $field[2] . ')';
                        }
                        $sqlArray[] = 'ALTER TABLE `' . $table . '` ADD ' . ($downgradeThis ? 'INDEX' : $field[1]) . ' `' . $field[0] . '` (`' . $field[0] . '`' . $extra . ');';
                    }
                }
                break;
            case 'adminTable':
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `admin_settings` (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`setting` varchar(255) COLLATE utf8_bin NOT NULL,
					`value` text COLLATE utf8_bin NOT NULL,
					PRIMARY KEY (`id`)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
                $sqlArray[] = "INSERT INTO `admin_settings` (`setting`, `value`) VALUES ('db_version', '2.4.0');";
                break;
            case '2.4.18':
                $sqlArray[] = "ALTER TABLE `users` ADD `current_login` INT(11) DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `users` ADD `last_login` INT(11) DEFAULT 0;";
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `event_delegations` (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`org_id` int(11) NOT NULL,
					`requester_org_id` int(11) NOT NULL,
					`event_id` int(11) NOT NULL,
					`message` text,
					`distribution` tinyint(4) NOT NULL DEFAULT  '-1',
					`sharing_group_id` int(11),
					PRIMARY KEY (`id`),
					KEY `org_id` (`org_id`),
					KEY `event_id` (`event_id`)
					) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
                break;
            case '2.4.19':
                $sqlArray[] = "DELETE FROM `shadow_attributes` WHERE `event_uuid` = '';";
                break;
            case '2.4.20':
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `shadow_attribute_correlations` (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`org_id` int(11) NOT NULL,
					`value` text NOT NULL,
					`distribution` tinyint(4) NOT NULL,
					`a_distribution` tinyint(4) NOT NULL,
					`sharing_group_id` int(11),
					`a_sharing_group_id` int(11),
					`attribute_id` int(11) NOT NULL,
					`1_shadow_attribute_id` int(11) NOT NULL,
					`event_id` int(11) NOT NULL,
					`1_event_id` int(11) NOT NULL,
					`info` text COLLATE utf8_bin NOT NULL,
					PRIMARY KEY (`id`),
					KEY `org_id` (`org_id`),
					KEY `attribute_id` (`attribute_id`),
					KEY `a_sharing_group_id` (`a_sharing_group_id`),
					KEY `event_id` (`event_id`),
					KEY `1_event_id` (`event_id`),
					KEY `sharing_group_id` (`sharing_group_id`),
					KEY `1_shadow_attribute_id` (`1_shadow_attribute_id`)
					) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
                break;
            case '2.4.25':
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `feeds` (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`name` varchar(255) COLLATE utf8_bin NOT NULL,
					`provider` varchar(255) COLLATE utf8_bin NOT NULL,
					`url` varchar(255) COLLATE utf8_bin NOT NULL,
					`rules` text COLLATE utf8_bin NOT NULL,
					`enabled` BOOLEAN NOT NULL,
					`distribution` tinyint(4) NOT NULL,
					`sharing_group_id` int(11) NOT NULL,
					`tag_id` int(11) NOT NULL,
					`default` tinyint(1) NOT NULL,
					PRIMARY KEY (`id`)
					) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
                break;
            case '2.4.32':
                $sqlArray[] = "ALTER TABLE `roles` ADD `perm_tag_editor` tinyint(1) NOT NULL DEFAULT 0;";
                $sqlArray[] = 'UPDATE `roles` SET `perm_tag_editor` = 1 WHERE `perm_tagger` = 1;';
                break;
            case '2.4.33':
                $sqlArray[] = "ALTER TABLE `users` ADD `force_logout` tinyint(1) NOT NULL DEFAULT 0;";
                break;
            case '2.4.38':
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `warninglists` (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`name` varchar(255) COLLATE utf8_bin NOT NULL,
					`type` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT 'string',
					`description` text COLLATE utf8_bin NOT NULL,
					`version` int(11) NOT NULL DEFAULT 1,
					`enabled` tinyint(1) NOT NULL DEFAULT 0,
					`warninglist_entry_count` int(11) unsigned DEFAULT NULL,
					PRIMARY KEY (`id`)
					) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `warninglist_entries` (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`value` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
					`warninglist_id` int(11) NOT NULL,
					PRIMARY KEY (`id`)
					) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `warninglist_types` (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`type` varchar(255) COLLATE utf8_bin NOT NULL,
					`warninglist_id` int(11) NOT NULL,
					PRIMARY KEY (`id`)
					) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
                break;
            case '2.4.39':
                $sqlArray[] = "ALTER TABLE `users` ADD `certif_public` longtext COLLATE utf8_bin AFTER `gpgkey`;";
                $sqlArray[] = 'ALTER TABLE `logs` MODIFY COLUMN `title` text, MODIFY COLUMN `change` text;';
                break;
            case '2.4.40':
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `favourite_tags` (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`tag_id` int(11) NOT NULL,
					`user_id` int(11) NOT NULL,
					PRIMARY KEY (`id`),
					INDEX `user_id` (`user_id`),
					INDEX `tag_id` (`tag_id`)
					) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
                break;
            case '2.4.42':
                $sqlArray[] = "ALTER TABLE `attributes` ADD `deleted` tinyint(1) NOT NULL DEFAULT 0;";
                break;
            case '2.4.44':
                $sqlArray[] = "UPDATE `servers` SET `url` = TRIM(TRAILING '/' FROM `url`);";
                break;
            case '2.4.45':
                $sqlArray[] = 'ALTER TABLE `users` CHANGE `newsread` `newsread` int(11) unsigned;';
                $sqlArray[] = 'UPDATE `users` SET `newsread` = 0;';
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `news` (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`message` text COLLATE utf8_bin NOT NULL,
					`title` text COLLATE utf8_bin NOT NULL,
					`user_id` int(11) NOT NULL,
					`date_created` int(11) unsigned NOT NULL,
					PRIMARY KEY (`id`)
					) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
                break;
            case '2.4.49':
                // table: users
                $sqlArray[] = "ALTER TABLE `users` ALTER COLUMN `server_id` SET DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `users` ALTER COLUMN `autoalert` SET DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `users` ALTER COLUMN `invited_by` SET DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `users` ALTER COLUMN `nids_sid` SET DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `users` ALTER COLUMN `termsaccepted` SET DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `users` ALTER COLUMN `role_id` SET DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `users` ALTER COLUMN `change_pw` SET DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `users` ALTER COLUMN `contactalert` SET DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `users` ALTER COLUMN `disabled` SET DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `users` MODIFY `authkey` varchar(40) COLLATE utf8_bin DEFAULT NULL;";
                $sqlArray[] = "ALTER TABLE `users` MODIFY `gpgkey` longtext COLLATE utf8_bin;";
                // table: events
                $sqlArray[] = "ALTER TABLE `events` ALTER COLUMN `publish_timestamp` SET DEFAULT 0;";
                // table: jobs
                $sqlArray[] = "ALTER TABLE `jobs` ALTER COLUMN `org_id` SET DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `jobs` MODIFY `process_id` varchar(32) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL;";
                // table: organisations
                $sqlArray[] = "ALTER TABLE `organisations` ALTER COLUMN `created_by` SET DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `organisations` MODIFY `uuid` varchar(40) COLLATE utf8_bin DEFAULT NULL;"; // https://github.com/MISP/MISP/pull/1260
                // table: logs
                $sqlArray[] = "ALTER TABLE `logs` MODIFY `title` text CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL;";
                $sqlArray[] = "ALTER TABLE `logs` MODIFY `change` text CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL;";
                $sqlArray[] = "ALTER TABLE `logs` MODIFY `description` text CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL;";
                // table: servers
                $sqlArray[] = "ALTER TABLE `servers` DROP `lastfetchedid`;"; // git commit hash d4c393897e8666fbbf04443a97d60c508700f5b4
                $sqlArray[] = "ALTER TABLE `servers` MODIFY `cert_file` varchar(255) COLLATE utf8_bin DEFAULT NULL;";
                // table: feeds
                $sqlArray[] = "ALTER TABLE `feeds` ALTER COLUMN `sharing_group_id` SET DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `feeds` ALTER COLUMN `tag_id` SET DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `feeds` MODIFY `rules` text COLLATE utf8_bin DEFAULT NULL;";
                // DB changes to support https://github.com/MISP/MISP/pull/1334
                $sqlArray[] = "ALTER TABLE `roles` ADD `perm_delegate` tinyint(1) NOT NULL DEFAULT 0 AFTER `perm_publish`;";
                $sqlArray[] = "UPDATE `roles` SET `perm_delegate` = 1 WHERE `perm_publish` = 1;";
                // DB changes to solve https://github.com/MISP/MISP/issues/1354
                $sqlArray[] = "ALTER TABLE `taxonomy_entries` MODIFY `expanded` text COLLATE utf8_bin;";
                $sqlArray[] = "ALTER TABLE `taxonomy_predicates` MODIFY `expanded` text COLLATE utf8_bin;";
                // Sharing group propagate to instances freely setting
                $sqlArray[] = "ALTER TABLE `sharing_groups` ADD `roaming` tinyint(1) NOT NULL DEFAULT 0;";
                // table: shadow_attributes
                $sqlArray[] = "ALTER TABLE `shadow_attributes` MODIFY `email` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL;";
                // table: tasks
                $sqlArray[] = "ALTER TABLE `tasks` CHANGE `job_id` `process_id` varchar(32) DEFAULT NULL;";
                // Adding tag org restrictions
                $sqlArray[] = "ALTER TABLE `tags` ADD `org_id` int(11) NOT NULL DEFAULT 0;";
                $sqlArray[] = 'ALTER TABLE `tags` ADD INDEX `org_id` (`org_id`);';
                $this->__dropIndex('tags', 'org_id');
                break;
            case '2.4.50':
                $sqlArray[] = 'ALTER TABLE `cake_sessions` ADD INDEX `expires` (`expires`);';
                $sqlArray[] = "ALTER TABLE `users` ADD `certif_public` longtext COLLATE utf8_bin AFTER `gpgkey`;";
                $sqlArray[] = "ALTER TABLE `servers` ADD `client_cert_file` varchar(255) COLLATE utf8_bin DEFAULT NULL;";
                $this->__dropIndex('cake_sessions', 'expires');
                break;
            case '2.4.51':
                $sqlArray[] = 'ALTER TABLE `servers` ADD `internal` tinyint(1) NOT NULL DEFAULT 0;';
                $sqlArray[] = 'ALTER TABLE `roles` ADD `default_role` tinyint(1) NOT NULL DEFAULT 0;';
                break;
            case '2.4.52':
                $sqlArray[] = "ALTER TABLE feeds ADD source_format varchar(255) COLLATE utf8_bin DEFAULT 'misp';";
                $sqlArray[] = 'ALTER TABLE feeds ADD fixed_event tinyint(1) NOT NULL DEFAULT 0;';
                $sqlArray[] = 'ALTER TABLE feeds ADD delta_merge tinyint(1) NOT NULL DEFAULT 0;';
                $sqlArray[] = 'ALTER TABLE feeds ADD event_id int(11) NOT NULL DEFAULT 0;';
                $sqlArray[] = 'ALTER TABLE feeds ADD publish tinyint(1) NOT NULL DEFAULT 0;';
                $sqlArray[] = 'ALTER TABLE feeds ADD override_ids tinyint(1) NOT NULL DEFAULT 0;';
                $sqlArray[] = "ALTER TABLE feeds ADD settings text NOT NULL DEFAULT '';";
                break;
            case '2.4.56':
                $sqlArray[] =
                    "CREATE TABLE IF NOT EXISTS galaxies (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`uuid` varchar(255) COLLATE utf8_bin NOT NULL,
					`name` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT '',
					`type` varchar(255) COLLATE utf8_bin NOT NULL,
					`description` text COLLATE utf8_bin NOT NULL,
					`version` varchar(255) COLLATE utf8_bin NOT NULL,
					PRIMARY KEY (id)
					) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;";

                $this->__addIndex('galaxies', 'name');
                $this->__addIndex('galaxies', 'uuid');
                $this->__addIndex('galaxies', 'type');

                $sqlArray[] =
                    "CREATE TABLE IF NOT EXISTS galaxy_clusters (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`uuid` varchar(255) COLLATE utf8_bin NOT NULL,
					`type` varchar(255) COLLATE utf8_bin NOT NULL,
					`value` text COLLATE utf8_bin NOT NULL,
					`tag_name` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT '',
					`description` text COLLATE utf8_bin NOT NULL,
					`galaxy_id` int(11) NOT NULL,
					`source` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT '',
					`authors` text COLLATE utf8_bin NOT NULL,
					PRIMARY KEY (id)
					) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;";

                $this->__addIndex('galaxy_clusters', 'value', 255);
                $this->__addIndex('galaxy_clusters', 'tag_name');
                $this->__addIndex('galaxy_clusters', 'uuid');
                $this->__addIndex('galaxy_clusters', 'type');

                $sqlArray[] =
                    "CREATE TABLE IF NOT EXISTS galaxy_elements (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`galaxy_cluster_id` int(11) NOT NULL,
					`key` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT '',
					`value` text COLLATE utf8_bin NOT NULL,
					PRIMARY KEY (id)
					) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin;";

                $this->__addIndex('galaxy_elements', 'key');
                $this->__addIndex('galaxy_elements', 'value', 255);

                $sqlArray[] =
                    "CREATE TABLE IF NOT EXISTS galaxy_reference (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`galaxy_cluster_id` int(11) NOT NULL,
					`referenced_galaxy_cluster_id` int(11) NOT NULL,
					`referenced_galaxy_cluster_uuid` varchar(255) COLLATE utf8_bin NOT NULL,
					`referenced_galaxy_cluster_type` text COLLATE utf8_bin NOT NULL,
					`referenced_galaxy_cluster_value` text COLLATE utf8_bin NOT NULL,
					PRIMARY KEY (id)
					) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;";

                $this->__addIndex('galaxy_reference', 'galaxy_cluster_id');
                $this->__addIndex('galaxy_reference', 'referenced_galaxy_cluster_id');
                $this->__addIndex('galaxy_reference', 'referenced_galaxy_cluster_value', 255);
                $this->__addIndex('galaxy_reference', 'referenced_galaxy_cluster_type', 255);

                break;
            case '2.4.57':
                $sqlArray[] = 'ALTER TABLE tags ADD hide_tag tinyint(1) NOT NULL DEFAULT 0;';
                // new indeces to match the changes in #1766
                $this->__dropIndex('correlations', '1_event_id');
                $this->__addIndex('correlations', '1_event_id');
                $this->__addIndex('warninglist_entries', 'warninglist_id');
                break;
            case '2.4.58':
                $sqlArray[] = "ALTER TABLE `events` ADD `disable_correlation` tinyint(1) NOT NULL DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `attributes` ADD `disable_correlation` tinyint(1) NOT NULL DEFAULT 0;";
                break;
            case '2.4.59':
                $sqlArray[] = "ALTER TABLE taxonomy_entries ADD colour varchar(7) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '';";
                $sqlArray[] = "ALTER TABLE taxonomy_predicates ADD colour varchar(7) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '';";
                break;
            case '2.4.60':
                if ($dataSource == 'Database/Mysql') {
                    $sqlArray[] = 'CREATE TABLE IF NOT EXISTS `attribute_tags` (
								`id` int(11) NOT NULL AUTO_INCREMENT,
								`attribute_id` int(11) NOT NULL,
								`event_id` int(11) NOT NULL,
								`tag_id` int(11) NOT NULL,
								PRIMARY KEY (`id`)
							) ENGINE=InnoDB DEFAULT CHARSET=utf8;';
                    $sqlArray[] = 'ALTER TABLE `attribute_tags` ADD INDEX `attribute_id` (`attribute_id`);';
                    $sqlArray[] = 'ALTER TABLE `attribute_tags` ADD INDEX `event_id` (`event_id`);';
                    $sqlArray[] = 'ALTER TABLE `attribute_tags` ADD INDEX `tag_id` (`tag_id`);';
                } elseif ($dataSource == 'Database/Postgres') {
                    $sqlArray[] = 'CREATE TABLE IF NOT EXISTS attribute_tags (
								id bigserial NOT NULL,
								attribute_id bigint NOT NULL,
								event_id bigint NOT NULL,
								tag_id bigint NOT NULL,
								PRIMARY KEY (id)
							);';
                    $sqlArray[] = 'CREATE INDEX idx_attribute_tags_attribute_id ON attribute_tags (attribute_id);';
                    $sqlArray[] = 'CREATE INDEX idx_attribute_tags_event_id ON attribute_tags (event_id);';
                    $sqlArray[] = 'CREATE INDEX idx_attribute_tags_tag_id ON attribute_tags (tag_id);';
                }
                break;
            case '2.4.61':
                $sqlArray[] = 'ALTER TABLE feeds ADD input_source varchar(255) COLLATE utf8_bin NOT NULL DEFAULT "network";';
                $sqlArray[] = 'ALTER TABLE feeds ADD delete_local_file tinyint(1) DEFAULT 0;';
                $indexArray[] = array('feeds', 'input_source');
                break;
            case '2.4.62':
                $sqlArray[] = 'ALTER TABLE logs CHANGE `org` `org` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT "";';
                $sqlArray[] = 'ALTER TABLE logs CHANGE `email` `email` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT "";';
                $sqlArray[] = 'ALTER TABLE logs CHANGE `change` `change` text COLLATE utf8_bin NOT NULL DEFAULT "";';
                break;
            case '2.4.63':
                $sqlArray[] = 'ALTER TABLE events DROP COLUMN org;';
                $sqlArray[] = 'ALTER TABLE events DROP COLUMN orgc;';
                $sqlArray[] = 'ALTER TABLE event_blacklists CHANGE comment comment TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci;';
                break;
            case '2.4.64':
                $indexArray[] = array('feeds', 'input_source');
                $indexArray[] = array('attributes', 'value1', 255);
                $indexArray[] = array('attributes', 'value2', 255);
                $indexArray[] = array('attributes', 'type');
                $indexArray[] = array('galaxy_reference', 'galaxy_cluster_id');
                $indexArray[] = array('galaxy_reference', 'referenced_galaxy_cluster_id');
                $indexArray[] = array('galaxy_reference', 'referenced_galaxy_cluster_value', 255);
                $indexArray[] = array('galaxy_reference', 'referenced_galaxy_cluster_type', 255);
                $indexArray[] = array('correlations', '1_event_id');
                $indexArray[] = array('warninglist_entries', 'warninglist_id');
                $indexArray[] = array('galaxy_clusters', 'value', 255);
                $indexArray[] = array('galaxy_clusters', 'tag_name');
                $indexArray[] = array('galaxy_clusters', 'uuid');
                $indexArray[] = array('galaxy_clusters', 'type');
                $indexArray[] = array('galaxies', 'name');
                $indexArray[] = array('galaxies', 'uuid');
                $indexArray[] = array('galaxies', 'type');
                break;
            case '2.4.65':
                $sqlArray[] = 'ALTER TABLE feeds CHANGE `enabled` `enabled` tinyint(1) DEFAULT 0;';
                $sqlArray[] = 'ALTER TABLE feeds CHANGE `default` `default` tinyint(1) DEFAULT 0;';
                $sqlArray[] = 'ALTER TABLE feeds CHANGE `distribution` `distribution` tinyint(4) NOT NULL DEFAULT 0;';
                $sqlArray[] = 'ALTER TABLE feeds CHANGE `sharing_group_id` `sharing_group_id` int(11) NOT NULL DEFAULT 0;';
                $sqlArray[] = 'ALTER TABLE attributes CHANGE `comment` `comment` text COLLATE utf8_bin;';
                break;
            case '2.4.66':
                $sqlArray[] = 'ALTER TABLE shadow_attributes CHANGE old_id old_id int(11) DEFAULT 0;';
                $sqlArray[] = 'ALTER TABLE sightings ADD COLUMN uuid varchar(255) COLLATE utf8_bin DEFAULT "";';
                $sqlArray[] = 'ALTER TABLE sightings ADD COLUMN source varchar(255) COLLATE utf8_bin DEFAULT "";';
                $sqlArray[] = 'ALTER TABLE sightings ADD COLUMN type int(11) DEFAULT 0;';
                $indexArray[] = array('sightings', 'uuid');
                $indexArray[] = array('sightings', 'source');
                $indexArray[] = array('sightings', 'type');
                $indexArray[] = array('attributes', 'category');
                $indexArray[] = array('shadow_attributes', 'category');
                $indexArray[] = array('shadow_attributes', 'type');
                break;
            case '2.4.67':
                $sqlArray[] = "ALTER TABLE `roles` ADD `perm_sighting` tinyint(1) NOT NULL DEFAULT 0;";
                $sqlArray[] = 'UPDATE `roles` SET `perm_sighting` = 1 WHERE `perm_add` = 1;';
                break;
            case '2.4.68':
                $sqlArray[] = 'ALTER TABLE events CHANGE attribute_count attribute_count int(11) unsigned DEFAULT 0;';
                $sqlArray[] = 'CREATE TABLE IF NOT EXISTS `event_blacklists` (
				  `id` int(11) NOT NULL AUTO_INCREMENT,
				  `event_uuid` varchar(40) COLLATE utf8_bin NOT NULL,
				  `created` datetime NOT NULL,
				  `event_info` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
				  `comment` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci,
				  `event_orgc` VARCHAR( 255 ) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
				  PRIMARY KEY (`id`)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;';
                $indexArray[] = array('event_blacklists', 'event_uuid');
                $indexArray[] = array('event_blacklists', 'event_orgc');
                $sqlArray[] = 'CREATE TABLE IF NOT EXISTS `org_blacklists` (
				  `id` int(11) NOT NULL AUTO_INCREMENT,
				  `org_uuid` varchar(40) COLLATE utf8_bin NOT NULL,
				  `created` datetime NOT NULL,
				  `org_name` varchar(255) COLLATE utf8_bin NOT NULL,
				  `comment` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci,
				  PRIMARY KEY (`id`),
				  INDEX `org_uuid` (`org_uuid`),
				  INDEX `org_name` (`org_name`)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;';
                $indexArray[] = array('org_blacklists', 'org_uuid');
                $indexArray[] = array('org_blacklists', 'org_name');
                $sqlArray[] = "ALTER TABLE shadow_attributes CHANGE proposal_to_delete proposal_to_delete BOOLEAN DEFAULT 0";
                $sqlArray[] = "ALTER TABLE taxonomy_predicates CHANGE colour colour varchar(7) CHARACTER SET utf8 COLLATE utf8_bin;";
                $sqlArray[] = "ALTER TABLE taxonomy_entries CHANGE colour colour varchar(7) CHARACTER SET utf8 COLLATE utf8_bin;";
                break;
            case '2.4.69':
                $sqlArray[] = "ALTER TABLE taxonomy_entries CHANGE colour colour varchar(7) CHARACTER SET utf8 COLLATE utf8_bin;";
                $sqlArray[] = "ALTER TABLE users ADD COLUMN date_created bigint(20);";
                $sqlArray[] = "ALTER TABLE users ADD COLUMN date_modified bigint(20);";
                break;
            case '2.4.71':
                $sqlArray[] = "UPDATE attributes SET comment = '' WHERE comment is NULL;";
                $sqlArray[] = "ALTER TABLE attributes CHANGE comment comment text COLLATE utf8_bin NOT NULL;";
                break;
            case '2.4.72':
                $sqlArray[] = 'ALTER TABLE feeds ADD lookup_visible tinyint(1) DEFAULT 0;';
                break;
            case '2.4.73':
                $sqlArray[] = 'ALTER TABLE `servers` ADD `unpublish_event` tinyint(1) NOT NULL DEFAULT 0;';
                $sqlArray[] = 'ALTER TABLE `servers` ADD `publish_without_email` tinyint(1) NOT NULL DEFAULT 0;';
                break;
            case '2.4.75':
                $this->__dropIndex('attributes', 'value1');
                $this->__dropIndex('attributes', 'value2');
                $this->__addIndex('attributes', 'value1', 255);
                $this->__addIndex('attributes', 'value2', 255);
                break;
            case '2.4.77':
                $sqlArray[] = 'ALTER TABLE `users` CHANGE `password` `password` VARCHAR(255) COLLATE utf8_bin NOT NULL;';
                break;
            case '2.4.78':
                $sqlArray[] = "ALTER TABLE galaxy_clusters ADD COLUMN version int(11) DEFAULT 0;";
                $this->__addIndex('galaxy_clusters', 'version');
                $this->__addIndex('galaxy_clusters', 'galaxy_id');
                $this->__addIndex('galaxy_elements', 'galaxy_cluster_id');
                break;
            case '2.4.80':
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS objects (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`name` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
					`meta-category` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
					`description` text CHARACTER SET utf8 COLLATE utf8_unicode_ci,
					`template_uuid` varchar(40) COLLATE utf8_bin DEFAULT NULL,
					`template_version` int(11) NOT NULL,
					`event_id` int(11) NOT NULL,
					`uuid` varchar(40) COLLATE utf8_bin DEFAULT NULL,
					`timestamp` int(11) NOT NULL DEFAULT 0,
					`distribution` tinyint(4) NOT NULL DEFAULT 0,
					`sharing_group_id` int(11),
					`comment` text COLLATE utf8_bin NOT NULL,
					`deleted` TINYINT(1) NOT NULL DEFAULT 0,
					PRIMARY KEY (id),
					INDEX `name` (`name`),
					INDEX `template_uuid` (`template_uuid`),
					INDEX `template_version` (`template_version`),
					INDEX `meta-category` (`meta-category`),
					INDEX `event_id` (`event_id`),
					INDEX `uuid` (`uuid`),
					INDEX `timestamp` (`timestamp`),
					INDEX `distribution` (`distribution`),
					INDEX `sharing_group_id` (`sharing_group_id`)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8;";

                $sqlArray[] = "CREATE TABLE IF NOT EXISTS object_references (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`uuid` varchar(40) COLLATE utf8_bin DEFAULT NULL,
					`timestamp` int(11) NOT NULL DEFAULT 0,
					`object_id` int(11) NOT NULL,
					`event_id` int(11) NOT NULL,
					`object_uuid` varchar(40) COLLATE utf8_bin DEFAULT NULL,
					`referenced_uuid` varchar(40) COLLATE utf8_bin DEFAULT NULL,
					`referenced_id` int(11) NOT NULL,
					`referenced_type` int(11) NOT NULL DEFAULT 0,
					`relationship_type` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
					`comment` text COLLATE utf8_bin NOT NULL,
					`deleted` TINYINT(1) NOT NULL DEFAULT 0,
					PRIMARY KEY (id),
					INDEX `object_uuid` (`object_uuid`),
				  INDEX `referenced_uuid` (`referenced_uuid`),
				  INDEX `timestamp` (`timestamp`),
				  INDEX `object_id` (`object_id`),
				  INDEX `referenced_id` (`referenced_id`),
				  INDEX `relationship_type` (`relationship_type`)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8;";

                $sqlArray[] = "CREATE TABLE IF NOT EXISTS object_relationships (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`version` int(11) NOT NULL,
					`name` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
					`description` text COLLATE utf8_bin NOT NULL,
					`format` text COLLATE utf8_bin NOT NULL,
					PRIMARY KEY (id),
					INDEX `name` (`name`)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8;";


                $sqlArray[] = "CREATE TABLE IF NOT EXISTS object_templates (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`user_id` int(11) NOT NULL,
					`org_id` int(11) NOT NULL,
					`uuid` varchar(40) COLLATE utf8_bin DEFAULT NULL,
					`name` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
					`meta-category` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
					`description` text COLLATE utf8_bin,
					`version` int(11) NOT NULL,
					`requirements` text COLLATE utf8_bin,
					`fixed` tinyint(1) NOT NULL DEFAULT 0,
					`active` tinyint(1) NOT NULL DEFAULT 0,
					PRIMARY KEY (id),
					INDEX `user_id` (`user_id`),
					INDEX `org_id` (`org_id`),
					INDEX `uuid` (`uuid`),
					INDEX `name` (`name`),
					INDEX `meta-category` (`meta-category`)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8;";

                $sqlArray[] = "CREATE TABLE IF NOT EXISTS object_template_elements (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`object_template_id` int(11) NOT NULL,
					`object_relation` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
					`type` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
					`ui-priority` int(11) NOT NULL,
					`categories` text COLLATE utf8_bin,
					`sane_default` text COLLATE utf8_bin,
					`values_list` text COLLATE utf8_bin,
					`description` text COLLATE utf8_bin,
					`disable_correlation` tinyint(1) NOT NULL DEFAULT 0,
					`multiple` tinyint(1) NOT NULL DEFAULT 0,
					PRIMARY KEY (id),
					INDEX `object_relation` (`object_relation`),
					INDEX `type` (`type`)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8;";

                $sqlArray[] = 'ALTER TABLE `logs` CHANGE `model` `model` VARCHAR(80) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL;';
                $sqlArray[] = 'ALTER TABLE `logs` CHANGE `action` `action` VARCHAR(80) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL;';

                $sqlArray[] = 'ALTER TABLE attributes ADD object_id int(11) NOT NULL DEFAULT 0;';
                $sqlArray[] = 'ALTER TABLE attributes ADD object_relation varchar(255) COLLATE utf8_bin;';

                $sqlArray[] = "ALTER TABLE `roles` ADD `perm_object_template` tinyint(1) NOT NULL DEFAULT 0;";
                $sqlArray[] = 'UPDATE `roles` SET `perm_object_template` = 1 WHERE `perm_site_admin` = 1;';

                $indexArray[] = array('attributes', 'object_id');
                $indexArray[] = array('attributes', 'object_relation');
                break;
            case '2.4.81':
                $sqlArray[] = 'ALTER TABLE `galaxy_clusters` ADD `version` INT NOT NULL DEFAULT 0;';
                $sqlArray[] = 'ALTER TABLE `galaxies` ADD `icon` VARCHAR(255) COLLATE utf8_bin DEFAULT "";';
                break;
            case '2.4.82':
                $sqlArray[] = "ALTER TABLE organisations ADD restricted_to_domain text COLLATE utf8_bin;";
                break;
            case '2.4.83':
                $sqlArray[] = "ALTER TABLE object_template_elements CHANGE `disable_correlation` `disable_correlation` text COLLATE utf8_bin;";
                break;
            case '2.4.84':
                $sqlArray[] = "ALTER TABLE `tags` ADD `user_id` int(11) NOT NULL DEFAULT 0;";
                $sqlArray[] = 'ALTER TABLE `tags` ADD INDEX `user_id` (`user_id`);';
                break;
            case '2.4.85':
                $sqlArray[] = "ALTER TABLE `shadow_attributes` ADD `disable_correlation` tinyint(1) NOT NULL DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE object_template_elements CHANGE `disable_correlation` `disable_correlation` text COLLATE utf8_bin;";
                // yes, this may look stupid as hell to index a boolean flag - but thanks to the stupidity of MySQL/MariaDB this will
                // stop blocking other indexes to be used in queries where we also tests for the deleted flag.
                $indexArray[] = array('attributes', 'deleted');
                break;
            case '2.4.86':
                break;
            case '2.4.87':
                $sqlArray[] = "ALTER TABLE `feeds` ADD `headers` TEXT COLLATE utf8_bin;";
                break;
            case 1:
                $sqlArray[] = "ALTER TABLE `tags` ADD `user_id` int(11) NOT NULL DEFAULT 0;";
                $sqlArray[] = 'ALTER TABLE `tags` ADD INDEX `user_id` (`user_id`);';
                break;
            case 2:
            // rerun missing db entries
                $sqlArray[] = "ALTER TABLE users ADD COLUMN date_created bigint(20);";
                $sqlArray[] = "ALTER TABLE users ADD COLUMN date_modified bigint(20);";
                break;
            case 3:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `fuzzy_correlate_ssdeep` (
  											`id` int(11) NOT NULL AUTO_INCREMENT,
  											`chunk` varchar(12) NOT NULL,
  											`attribute_id` int(11) NOT NULL,
  											PRIMARY KEY (`id`)
											) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
                $this->__addIndex('fuzzy_correlate_ssdeep', 'chunk');
                $this->__addIndex('fuzzy_correlate_ssdeep', 'attribute_id');
                break;
            case 4:
                $sqlArray[] = 'ALTER TABLE `roles` ADD `memory_limit` VARCHAR(255) COLLATE utf8_bin DEFAULT "";';
                $sqlArray[] = 'ALTER TABLE `roles` ADD `max_execution_time` VARCHAR(255) COLLATE utf8_bin DEFAULT "";';
                $sqlArray[] = "ALTER TABLE `roles` ADD `restricted_to_site_admin` tinyint(1) NOT NULL DEFAULT 0;";
                break;
            case 5:
                $sqlArray[] = "ALTER TABLE `feeds` ADD `caching_enabled` tinyint(1) NOT NULL DEFAULT 0;";
                break;
            case 6:
                $sqlArray[] = "ALTER TABLE `events` ADD `extends_uuid` varchar(40) COLLATE utf8_bin DEFAULT '';";
                $indexArray[] = array('events', 'extends_uuid');
                break;
            case 7:
                $sqlArray[] = 'CREATE TABLE IF NOT EXISTS `noticelists` (
						`id` int(11) NOT NULL AUTO_INCREMENT,
						`name` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
						`expanded_name` text COLLATE utf8_unicode_ci NOT NULL,
						`ref` text COLLATE utf8_unicode_ci,
						`geographical_area` varchar(255) COLLATE utf8_unicode_ci,
						`version` int(11) NOT NULL DEFAULT 1,
						`enabled` tinyint(1) NOT NULL DEFAULT 0,
						PRIMARY KEY (`id`),
						INDEX `name` (`name`),
						INDEX `geographical_area` (`geographical_area`)
					) ENGINE=InnoDB DEFAULT CHARSET=utf8;';
                $sqlArray[] = 'CREATE TABLE IF NOT EXISTS `noticelist_entries` (
						`id` int(11) NOT NULL AUTO_INCREMENT,
						`noticelist_id` int(11) NOT NULL,
						`data` text COLLATE utf8_unicode_ci NOT NULL,
						PRIMARY KEY (`id`),
						INDEX `noticelist_id` (`noticelist_id`)
					) ENGINE=InnoDB DEFAULT CHARSET=utf8;';
            break;
            case 9:
                $sqlArray[] = 'ALTER TABLE galaxies ADD namespace varchar(255) COLLATE utf8_unicode_ci NOT NULL DEFAULT "misp";';
                $indexArray[] = array('galaxies', 'namespace');
                break;
            case 10:
                $sqlArray[] = "ALTER TABLE `roles` ADD `perm_publish_zmq` tinyint(1) NOT NULL DEFAULT 0;";
                break;
            case 11:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS event_locks (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`event_id` int(11) NOT NULL,
					`user_id` int(11) NOT NULL,
					`timestamp` int(11) NOT NULL DEFAULT 0,
					PRIMARY KEY (id),
					INDEX `event_id` (`event_id`),
					INDEX `user_id` (`user_id`),
					INDEX `timestamp` (`timestamp`)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
                break;
            case 12:
                $sqlArray[] = "ALTER TABLE `servers` ADD `skip_proxy` tinyint(1) NOT NULL DEFAULT 0;";
                break;
            case 13:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS event_graph (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`event_id` int(11) NOT NULL,
					`user_id` int(11) NOT NULL,
					`org_id` int(11) NOT NULL,
					`timestamp` int(11) NOT NULL DEFAULT 0,
					`network_name` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
					`network_json` MEDIUMTEXT NOT NULL,
					`preview_img` MEDIUMTEXT,
					PRIMARY KEY (id),
					INDEX `event_id` (`event_id`),
					INDEX `user_id` (`user_id`),
					INDEX `org_id` (`org_id`),
					INDEX `timestamp` (`timestamp`)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
                break;
            case 14:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `user_settings` (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`setting` varchar(255) COLLATE utf8_bin NOT NULL,
					`value` text COLLATE utf8_bin NOT NULL,
					`user_id` int(11) NOT NULL,
					INDEX `setting` (`setting`),
					INDEX `user_id` (`user_id`),
					PRIMARY KEY (`id`)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
                break;
            case 15:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS event_graph (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`event_id` int(11) NOT NULL,
					`user_id` int(11) NOT NULL,
					`org_id` int(11) NOT NULL,
					`timestamp` int(11) NOT NULL DEFAULT 0,
					`network_name` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
					`network_json` MEDIUMTEXT NOT NULL,
					`preview_img` MEDIUMTEXT,
					PRIMARY KEY (id),
					INDEX `event_id` (`event_id`),
					INDEX `user_id` (`user_id`),
					INDEX `org_id` (`org_id`),
					INDEX `timestamp` (`timestamp`)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
                break;
            case 18:
                $sqlArray[] = 'ALTER TABLE `taxonomy_predicates` ADD COLUMN description text CHARACTER SET UTF8 collate utf8_bin;';
                $sqlArray[] = 'ALTER TABLE `taxonomy_entries` ADD COLUMN description text CHARACTER SET UTF8 collate utf8_bin;';
                $sqlArray[] = 'ALTER TABLE `taxonomy_predicates` ADD COLUMN exclusive tinyint(1) DEFAULT 0;';
                break;
            case 19:
                $sqlArray[] = 'ALTER TABLE `taxonomies` ADD COLUMN exclusive tinyint(1) DEFAULT 0;';
                break;
            case 20:
                $sqlArray[] = "ALTER TABLE `servers` ADD `skip_proxy` tinyint(1) NOT NULL DEFAULT 0;";
                break;
            case 21:
                $sqlArray[] = 'ALTER TABLE `tags` ADD COLUMN numerical_value int(11) NULL;';
                $sqlArray[] = 'ALTER TABLE `taxonomy_predicates` ADD COLUMN numerical_value int(11) NULL;';
                $sqlArray[] = 'ALTER TABLE `taxonomy_entries` ADD COLUMN numerical_value int(11) NULL;';
                break;
			case 22:
				$sqlArray[] = 'ALTER TABLE `object_references` MODIFY `deleted` tinyint(1) NOT NULL default 0;';
				break;
            case 'fixNonEmptySharingGroupID':
                $sqlArray[] = 'UPDATE `events` SET `sharing_group_id` = 0 WHERE `distribution` != 4;';
                $sqlArray[] = 'UPDATE `attributes` SET `sharing_group_id` = 0 WHERE `distribution` != 4;';
                break;
            case 'cleanupAfterUpgrade':
                $sqlArray[] = 'ALTER TABLE `events` DROP `org`;';
                $sqlArray[] = 'ALTER TABLE `events` DROP `orgc`;';
                $sqlArray[] = 'ALTER TABLE `correlations` DROP `org`;';
                $sqlArray[] = 'ALTER TABLE `jobs` DROP `org`;';
                $sqlArray[] = 'ALTER TABLE `servers` DROP `org`;';
                $sqlArray[] = 'ALTER TABLE `servers` DROP `organization`;';
                $sqlArray[] = 'ALTER TABLE `shadow_attributes` DROP `org`;';
                $sqlArray[] = 'ALTER TABLE `shadow_attributes` DROP `event_org`;';
                $sqlArray[] = 'ALTER TABLE `threads` DROP `org`;';
                $sqlArray[] = 'ALTER TABLE `users` DROP `org`;';
                break;
            default:
                return false;
                break;
        }
        foreach ($sqlArray as $sql) {
            try {
                $this->query($sql);
                $this->Log->create();
                $this->Log->save(array(
                        'org' => 'SYSTEM',
                        'model' => 'Server',
                        'model_id' => 0,
                        'email' => 'SYSTEM',
                        'action' => 'update_database',
                        'user_id' => 0,
                        'title' => 'Successfuly executed the SQL query for ' . $command,
                        'change' => 'The executed SQL query was: ' . $sql
                ));
            } catch (Exception $e) {
                $this->Log->create();
                $this->Log->save(array(
                        'org' => 'SYSTEM',
                        'model' => 'Server',
                        'model_id' => 0,
                        'email' => 'SYSTEM',
                        'action' => 'update_database',
                        'user_id' => 0,
                        'title' => 'Issues executing the SQL query for ' . $command,
                        'change' => 'The executed SQL query was: ' . $sql . PHP_EOL . ' The returned error is: ' . $e->getMessage()
                ));
            }
        }
        if (!empty($indexArray)) {
            if ($clean) {
                $this->cleanCacheFiles();
            }
            foreach ($indexArray as $iA) {
                if (isset($iA[2])) {
                    $this->__addIndex($iA[0], $iA[1], $iA[2]);
                } else {
                    $this->__addIndex($iA[0], $iA[1]);
                }
            }
        }
        if ($clean) {
            $this->cleanCacheFiles();
        }
        return true;
    }

    private function __dropIndex($table, $field)
    {
        $dataSourceConfig = ConnectionManager::getDataSource('default')->config;
        $dataSource = $dataSourceConfig['datasource'];
        $this->Log = ClassRegistry::init('Log');
        $indexCheckResult = array();
        if ($dataSource == 'Database/Mysql') {
            $indexCheck = "SELECT INDEX_NAME FROM INFORMATION_SCHEMA.STATISTICS WHERE table_schema=DATABASE() AND table_name='" . $table . "' AND index_name LIKE '" . $field . "%';";
            $indexCheckResult = $this->query($indexCheck);
        } elseif ($dataSource == 'Database/Postgres') {
            $pgIndexName = 'idx_' . $table . '_' . $field;
            $indexCheckResult[] = array('STATISTICS' => array('INDEX_NAME' => $pgIndexName));
        }
        foreach ($indexCheckResult as $icr) {
            if ($dataSource == 'Database/Mysql') {
                $dropIndex = 'ALTER TABLE ' . $table . ' DROP INDEX ' . $icr['STATISTICS']['INDEX_NAME'] . ';';
            } elseif ($dataSource == 'Database/Postgres') {
                $dropIndex = 'DROP INDEX IF EXISTS ' . $icr['STATISTICS']['INDEX_NAME'] . ';';
            }
            $result = true;
            try {
                $this->query($dropIndex);
            } catch (Exception $e) {
                $result = false;
            }
            $this->Log->create();
            $this->Log->save(array(
                    'org' => 'SYSTEM',
                    'model' => 'Server',
                    'model_id' => 0,
                    'email' => 'SYSTEM',
                    'action' => 'update_database',
                    'user_id' => 0,
                    'title' => ($result ? 'Removed index ' : 'Failed to remove index ') . $icr['STATISTICS']['INDEX_NAME'] . ' from ' . $table,
                    'change' => ($result ? 'Removed index ' : 'Failed to remove index ') . $icr['STATISTICS']['INDEX_NAME'] . ' from ' . $table,
            ));
        }
    }

    private function __addIndex($table, $field, $length = false)
    {
        $dataSourceConfig = ConnectionManager::getDataSource('default')->config;
        $dataSource = $dataSourceConfig['datasource'];
        $this->Log = ClassRegistry::init('Log');
        if ($dataSource == 'Database/Postgres') {
            $addIndex = "CREATE INDEX idx_" . $table . "_" . $field . " ON " . $table . " (" . $field . ");";
        } else {
            if (!$length) {
                $addIndex = "ALTER TABLE `" . $table . "` ADD INDEX `" . $field . "` (`" . $field . "`);";
            } else {
                $addIndex = "ALTER TABLE `" . $table . "` ADD INDEX `" . $field . "` (`" . $field . "`(" . $length . "));";
            }
        }
        $result = true;
        $duplicate = false;
        try {
            $this->query($addIndex);
        } catch (Exception $e) {
            $duplicate = (strpos($e->getMessage(), '1061') !== false);
            $result = false;
        }
        $this->Log->create();
        $this->Log->save(array(
                'org' => 'SYSTEM',
                'model' => 'Server',
                'model_id' => 0,
                'email' => 'SYSTEM',
                'action' => 'update_database',
                'user_id' => 0,
                'title' => ($result ? 'Added index ' : 'Failed to add index ') . $field . ' to ' . $table . ($duplicate ? ' (index already set)' : ''),
                'change' => ($result ? 'Added index ' : 'Failed to add index ') . $field . ' to ' . $table . ($duplicate ? ' (index already set)' : ''),
        ));
    }

    public function cleanCacheFiles()
    {
        Cache::clear();
        clearCache();
        $files = array();
        $files = array_merge($files, glob(CACHE . 'models' . DS . 'myapp*'));
        $files = array_merge($files, glob(CACHE . 'persistent' . DS . 'myapp*'));
        foreach ($files as $f) {
            if (is_file($f)) {
                unlink($f);
            }
        }
    }

    public function checkMISPVersion()
    {
        App::uses('Folder', 'Utility');
        $file = new File(ROOT . DS . 'VERSION.json', true);
        $version_array = json_decode($file->read(), true);
        $file->close();
        return $version_array;
    }

    public function validateAuthkey($value)
    {
        if (empty($value['authkey'])) {
            return 'Empty authkey found. Make sure you set the 40 character long authkey.';
        }
        if (!preg_match('/[a-z0-9]{40}/i', $value['authkey'])) {
            return 'The authkey has to be exactly 40 characters long and consist of alphanumeric characters.';
        }
        return true;
    }

    // alternative to the build in notempty/notblank validation functions, compatible with cakephp <= 2.6 and cakephp and cakephp >= 2.7
    public function valueNotEmpty($value)
    {
        $field = array_keys($value);
        $field = $field[0];
        $value[$field] = trim($value[$field]);
        if (!empty($value[$field])) {
            return true;
        }
        return ucfirst($field) . ' cannot be empty.';
    }

    public function valueIsID($value)
    {
        $field = array_keys($value);
        $field = $field[0];
        if (!is_numeric($value[$field]) || $value[$field] < 0) {
            return 'Invalid ' . ucfirst($field) . ' ID';
        }
        return true;
    }

    public function stringNotEmpty($value)
    {
        $field = array_keys($value);
        $field = $field[0];
        $value[$field] = trim($value[$field]);
        if (!isset($value[$field]) || ($value[$field] == false && $value[$field] !== "0")) {
            return ucfirst($field) . ' cannot be empty.';
        }
        return true;
    }

    public function runUpdates()
    {
        $this->AdminSetting = ClassRegistry::init('AdminSetting');
        $db = ConnectionManager::getDataSource('default');
        $tables = $db->listSources();
        $requiresLogout = false;
        // if we don't even have an admin table, time to create it.
        if (!in_array('admin_settings', $tables)) {
            $this->updateDatabase('adminTable');
            $requiresLogout = true;
        } else {
            $this->__runCleanDB();
            $db_version = $this->AdminSetting->find('all', array('conditions' => array('setting' => 'db_version')));
            if (count($db_version) > 1) {
                // we rgan into a bug where we have more than one db_version entry. This bug happened in some rare circumstances around 2.4.50-2.4.57
                foreach ($db_version as $k => $v) {
                    if ($k > 0) {
                        $this->AdminSetting->delete($v['AdminSetting']['id']);
                    }
                }
            }
            $db_version = $db_version[0];
            $updates = $this->__findUpgrades($db_version['AdminSetting']['value']);
            if (!empty($updates)) {
                foreach ($updates as $update => $temp) {
                    $this->updateMISP($update);
                    if ($temp) {
                        $requiresLogout = true;
                    }
                    $db_version['AdminSetting']['value'] = $update;
                    $this->AdminSetting->save($db_version);
                }
                $this->__queueCleanDB();
            }
        }
        if ($requiresLogout) {
            $this->updateDatabase('destroyAllSessions');
        }
    }

    private function __queueCleanDB()
    {
        $this->AdminSetting = ClassRegistry::init('AdminSetting');
        $cleanDB = $this->AdminSetting->find('first', array('conditions' => array('setting' => 'clean_db')));
        if (empty($cleanDB)) {
            $this->AdminSetting->create();
            $cleanDB = array('AdminSetting' => array('setting' => 'clean_db', 'value' => 1));
        } else {
            $cleanDB['AdminSetting']['value'] = 1;
        }
        $this->AdminSetting->save($cleanDB);
    }

    private function __runCleanDB()
    {
        $this->AdminSetting = ClassRegistry::init('AdminSetting');
        $cleanDB = $this->AdminSetting->find('first', array('conditions' => array('setting' => 'clean_db')));
        if (empty($cleanDB) || $cleanDB['AdminSetting']['value'] == 1) {
            $this->cleanCacheFiles();
            if (empty($cleanDB)) {
                $this->AdminSetting->create();
                $cleanDB = array('AdminSetting' => array('setting' => 'clean_db', 'value' => 0));
            } else {
                $cleanDB['AdminSetting']['value'] = 0;
            }
            $this->AdminSetting->save($cleanDB);
        }
    }

    private function __findUpgrades($db_version)
    {
        $updates = array();
        if (strpos($db_version, '.')) {
            $version = explode('.', $db_version);
            foreach ($this->old_db_changes as $major => $rest) {
                if ($major < $version[0]) {
                    continue;
                } elseif ($major == $version[0]) {
                    foreach ($rest as $minor => $hotfixes) {
                        if ($minor < $version[1]) {
                            continue;
                        } elseif ($minor == $version[1]) {
                            foreach ($hotfixes as $hotfix => $requiresLogout) {
                                if ($hotfix > $version[2]) {
                                    $updates[$major . '.' . $minor . '.' . $hotfix] = $requiresLogout;
                                }
                            }
                        } else {
                            foreach ($hotfixes as $hotfix => $requiresLogout) {
                                $updates[$major . '.' . $minor . '.' . $hotfix] = $requiresLogout;
                            }
                        }
                    }
                }
            }
            $db_version = 0;
        }
        foreach ($this->db_changes as $db_change => $requiresLogout) {
            if ($db_version < $db_change) {
                $updates[$db_change] = $requiresLogout;
            }
        }
        return $updates;
    }


    public function populateNotifications($user)
    {
        $notifications = array();
        $proposalCount = $this->_getProposalCount($user);
        $notifications['total'] = 0;
        $notifications['proposalCount'] = $proposalCount[0];
        $notifications['total'] += $proposalCount[0];
        $notifications['proposalEventCount'] = $proposalCount[1];
        if (Configure::read('MISP.delegation')) {
            $delegationCount = $this->_getDelegationCount($user);
            $notifications['total'] += $delegationCount;
            $notifications['delegationCount'] = $delegationCount;
        }
        return $notifications;
    }


    private function _getProposalCount($user)
    {
        $this->ShadowAttribute = ClassRegistry::init('ShadowAttribute');
        $this->ShadowAttribute->recursive = -1;
        $shadowAttributes = $this->ShadowAttribute->find('all', array(
                'recursive' => -1,
                'fields' => array('event_id', 'event_org_id'),
                'conditions' => array(
                        'ShadowAttribute.event_org_id' => $user['org_id'],
                        'ShadowAttribute.deleted' => 0,
                )));
        $results = array();
        $eventIds = array();
        $results[0] = count($shadowAttributes);
        foreach ($shadowAttributes as $sa) {
            if (!in_array($sa['ShadowAttribute']['event_id'], $eventIds)) {
                $eventIds[] = $sa['ShadowAttribute']['event_id'];
            }
        }
        $results[1] = count($eventIds);
        return $results;
    }

    private function _getDelegationCount($user)
    {
        $this->EventDelegation = ClassRegistry::init('EventDelegation');
        $delegations = $this->EventDelegation->find('count', array(
                'recursive' => -1,
                'conditions' => array(
                        'EventDelegation.org_id' => $user['org_id']
                )
        ));
        return $delegations;
    }

    public function checkFilename($filename)
    {
        return preg_match('@^([a-z0-9_.]+[a-z0-9_.\- ]*[a-z0-9_.\-]|[a-z0-9_.])+$@i', $filename);
    }

    public function setupRedis()
    {
        if (class_exists('Redis')) {
            if ($this->__redisConnection) {
                return $this->__redisConnection;
            }
            $redis = new Redis();
        } else {
            return false;
        }
        $host = Configure::read('MISP.redis_host') ? Configure::read('MISP.redis_host') : '127.0.0.1';
        $port = Configure::read('MISP.redis_port') ? Configure::read('MISP.redis_port') : 6379;
        $database = Configure::read('MISP.redis_database') ? Configure::read('MISP.redis_database') : 13;
        $pass = Configure::read('MISP.redis_password');
        if (!$redis->connect($host, $port)) {
            return false;
        }
        if (!empty($pass)) {
            $redis->auth($pass);
        }
        $redis->select($database);
        $this->__redisConnection = $redis;
        return $redis;
    }

    public function getPubSubTool()
    {
        if (!$this->loadedPubSubTool) {
            $this->loadPubSubTool();
        }
        return $this->loadedPubSubTool;
    }

    public function loadPubSubTool()
    {
        App::uses('PubSubTool', 'Tools');
        $pubSubTool = new PubSubTool();
        $pubSubTool->initTool();
        $this->loadedPubSubTool = $pubSubTool;
        return true;
    }

    public function getElasticSearchTool()
    {
        if (!$this->elasticSearchClient) {
            $this->loadElasticSearchTool();
        }
        return $this->elasticSearchClient;
    }

    public function loadElasticSearchTool()
    {
        App::uses('ElasticSearchClient', 'Tools');
        $client = new ElasticSearchClient();
        $client->initTool();
        $this->elasticSearchClient = $client;
    }

    public function getS3Client()
    {
        if (!$this->s3Client) {
            $this->s3Client = $this->loadS3Client();
        }

        return $this->s3Client;
    }

    public function loadS3Client()
    {
        App::uses('AWSS3Client', 'Tools');
        $client = new AWSS3Client();
        $client->initTool();
        return $client;
    }

    public function attachmentDirIsS3()
    {
        // Naive way to detect if we're working in S3
        return substr(Configure::read('MISP.attachments_dir'), 0, 2) === "s3";
    }

    public function checkVersionRequirements($versionString, $minVersion)
    {
        $version = explode('.', $versionString);
        $minVersion = explode('.', $minVersion);
        if (count($version) > $minVersion) {
            return true;
        }
        if (count($version) == 1) {
            return $minVersion <= $version;
        }
        return ($version[0] >= $minVersion[0] && $version[1] >= $minVersion[1] && $version[2] >= $minVersion[2]);
    }

    // generate a generic subquery - options needs to include conditions
    public function subQueryGenerator($model, $options, $lookupKey, $negation = false)
    {
        $db = $model->getDataSource();
        $defaults = array(
            'fields' => array('*'),
            'table' => $model->table,
            'alias' => $model->alias,
            'limit' => null,
            'offset' => null,
            'joins' => array(),
            'conditions' => array(),
            'group' => false
        );
        $params = array();
        foreach (array_keys($defaults) as $key) {
            if (isset($options[$key])) {
                $params[$key] = $options[$key];
            } else {
                $params[$key] = $defaults[$key];
            }
        }
        $subQuery = $db->buildStatement(
            $params,
            $model
        );
        if ($negation) {
            $subQuery = $lookupKey . ' NOT IN (' . $subQuery . ') ';
        } else {
            $subQuery = $lookupKey . ' IN (' . $subQuery . ') ';
        }
        $conditions = array(
            $db->expression($subQuery)->value
        );
        return $conditions;
    }

    // start a benchmark run for the given bench name
    public function benchmarkInit($name = 'default')
    {
        $this->__profiler[$name]['start'] = microtime(true);
        if (empty($this->__profiler[$name]['memory_start'])) {
            $this->__profiler[$name]['memory_start'] = memory_get_usage();
        }
        return true;
    }

    // calculate the duration from the init time to the current point in execution. Aggregate flagged executions will increment the duration instead of just setting it
    public function benchmark($name = 'default', $aggregate = false, $memory_chart = false)
    {
        if (!empty($this->__profiler[$name]['start'])) {
            if ($aggregate) {
                if (!isset($this->__profiler[$name]['duration'])) {
                    $this->__profiler[$name]['duration'] = 0;
                }
                if (!isset($this->__profiler[$name]['executions'])) {
                    $this->__profiler[$name]['executions'] = 0;
                }
                $this->__profiler[$name]['duration'] += microtime(true) - $this->__profiler[$name]['start'];
                $this->__profiler[$name]['executions']++;
                $currentUsage = memory_get_usage();
                if ($memory_chart) {
                    $this->__profiler[$name]['memory_chart'][] = $currentUsage - $this->__profiler[$name]['memory_start'];
                }
                if (
                    empty($this->__profiler[$name]['memory_peak']) ||
                    $this->__profiler[$name]['memory_peak'] < ($currentUsage - $this->__profiler[$name]['memory_start'])
                ) {
                    $this->__profiler[$name]['memory_peak'] = $currentUsage - $this->__profiler[$name]['memory_start'];
                }
            } else {
                $this->__profiler[$name]['memory_peak'] = memory_get_usage() - $this->__profiler[$name]['memory_start'];
                $this->__profiler[$name]['duration'] = microtime(true) - $this->__profiler[$name]['start'];
            }
        }
        return true;
    }

    // return the results of the benchmark(s). If no name is set all benchmark results are returned in an array.
    public function benchmarkResult($name = false)
    {
        if ($name) {
            return array($name => $this->__profiler[$name]['duration']);
        } else {
            $results = array();
            foreach ($this->__profiler as $name => $benchmark) {
                if (!empty($benchmark['duration'])) {
                    $results[$name] = $benchmark;
                    unset($results[$name]['start']);
                    unset($results[$name]['memory_start']);
                }
            }
            return $results;
        }
    }

    public function getRowCount($table = false)
    {
        if (empty($table)) {
            $table = $this->table;
        }
        $table_data = $this->query("show table status like '" . $table . "'");
        return $table_data[0]['TABLES']['Rows'];
    }

    public function benchmarkCustomAdd($valueToAdd = 0, $name = 'default', $customName = 'custom')
    {
        if (empty($this->__profiler[$name]['custom'][$customName])) {
            $this->__profiler[$name]['custom'][$customName] = 0;
        }
        $this->__profiler[$name]['custom'][$customName] += $valueToAdd;
    }

    private function __forceSettings()
    {
        $settingsToForce = array(
            'Session.autoRegenerate' => false,
            'Session.checkAgent' => false
        );
        $server = ClassRegistry::init('Server');
        foreach ($settingsToForce as $setting => $value) {
            $server->serverSettingsSaveValue($setting, $value);
        }
        return true;
    }

    public function setupHttpSocket($server, $HttpSocket = null)
    {
        if (empty($HttpSocket)) {
            App::uses('SyncTool', 'Tools');
            $syncTool = new SyncTool();
            $HttpSocket = $syncTool->setupHttpSocket($server);
        }
        return $HttpSocket;
    }

    public function setupSyncRequest($server)
    {
        $request = array(
                'header' => array(
                        'Authorization' => $server['Server']['authkey'],
                        'Accept' => 'application/json',
                        'Content-Type' => 'application/json'
                )
        );
        $request = $this->addHeaders($request);
        return $request;
    }

    public function addHeaders($request)
    {
        $version = $this->checkMISPVersion();
        $version = implode('.', $version);
        try {
            $commit = trim(shell_exec('git log --pretty="%H" -n1 HEAD'));
        } catch (Exception $e) {
            $commit = false;
        }
        $request['header']['MISP-version'] = $version;
        if ($commit) {
            $request['header']['commit'] = $commit;
        }
        return $request;
    }

    // take filters in the {"OR" => [foo], "NOT" => [bar]} format along with conditions and set the conditions
    public function generic_add_filter($conditions, &$filter, $keys, $searchall = false)
    {
        $operator_composition = array(
            'NOT' => 'AND',
            'OR' => 'OR',
            'AND' => 'AND'
        );
        if (!is_array($keys)) {
            $keys = array($keys);
        }
        if (!isset($filter['OR']) && !isset($filter['AND']) && !isset($filter['NOT'])) {
            return $conditions;
        }
        foreach ($filter as $operator => $filters) {
            $temp = array();
			if (!is_array($filters)) {
				$filters = array($filters);
			}
            foreach ($filters as $f) {
                // split the filter params into two lists, one for substring searches one for exact ones
                if ($f[strlen($f) - 1] === '%' || $f[0] === '%') {
                    foreach ($keys as $key) {
                        if ($operator === 'NOT') {
                            $temp[] = array($key . ' NOT LIKE' => $f);
                        } else {
                            $temp[] = array($key . ' LIKE' => $f);
                        }
                    }
                } else {
                    foreach ($keys as $key) {
                        if ($operator === 'NOT') {
                            $temp[$key . ' !='][] = $f;
                        } else {
                            $temp['OR'][$key][] = $f;
                        }
                    }
                }
            }
			if ($searchall && $operator === 'OR') {
				$conditions['AND']['OR'][] = array($operator_composition[$operator] => $temp);
			} else {
            	$conditions['AND'][] = array($operator_composition[$operator] => $temp);
			}
            if ($operator !== 'NOT') {
                unset($filter[$operator]);
            }
        }
        return $conditions;
    }

    /*
     * Get filters in one of the following formats:
     * [foo, bar]
     * ["OR" => [foo, bar], "NOT" => [baz]]
     * "foo"
     * "foo&&bar&&!baz"
     * and convert it into the same format ["OR" => [foo, bar], "NOT" => [baz]]
     */
    public function convert_filters($filter)
    {
        if (!is_array($filter)) {
            $temp = explode('&&', $filter);
            $filter = array();
            foreach ($temp as $f) {
                if ($f[0] === '!') {
                    $filter['NOT'][] = $f;
                } else {
                    $filter['OR'][] = $f;
                }
            }
            return $filter;
        }
        if (!isset($filter['OR']) && !isset($filter['NOT']) && !isset($filter['AND'])) {
            $temp = array();
            foreach ($filter as $param) {
                if ($param[0] === '!') {
                    $temp['NOT'][] = substr($param, 1);
                } else {
                    $temp['OR'][] = $param;
                }
            }
            $filter = $temp;
        }
        return $filter;
    }

	public function convert_to_memory_limit_to_mb($val) {
	    $val = trim($val);
		if ($val == -1) {
			// default to 8GB if no limit is set
			return 8 * 1024;
		}
		$unit = $val[strlen($val)-1];
		if (is_numeric($unit)) {
			$unit = 'b';
		} else {
			$val = intval($val);
		}
	    $unit = strtolower($unit);
	    switch($unit) {
	        case 'g':
	            $val *= 1024;
	        case 'm':
	            $val *= 1024;
	        case 'k':
	            $val *= 1024;
	    }
		return $val / (1024 * 1024);
	}
}
