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
App::uses('RandomTool', 'Tools');
App::uses('FileAccessTool', 'Tools');
App::uses('JsonTool', 'Tools');
App::uses('RedisTool', 'Tools');
App::uses('BetterCakeEventManager', 'Tools');
App::uses('Folder', 'Utility');

class AppModel extends Model
{
    /** @var PubSubTool */
    private static $loadedPubSubTool;

    /** @var KafkaPubTool */
    private $loadedKafkaPubTool;

    /** @var BackgroundJobsTool */
    private static $loadedBackgroundJobsTool;

    private $__profiler = array();

    /** @var AttachmentTool|null */
    private $attachmentTool;

    /** @var Workflow|null */
    private $Workflow;

    public $includeAnalystData;
    public $includeAnalystDataRecursive;

    // deprecated, use $db_changes
    // major -> minor -> hotfix -> requires_logout
    const OLD_DB_CHANGES = array(
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

    const DB_CHANGES = array(
        1 => false, 2 => false, 3 => false, 4 => true, 5 => false, 6 => false,
        7 => false, 8 => false, 9 => false, 10 => false, 11 => false, 12 => false,
        13 => false, 14 => false, 15 => false, 18 => false, 19 => false, 20 => false,
        21 => false, 22 => false, 23 => false, 24 => false, 25 => false, 26 => false,
        27 => false, 28 => false, 29 => false, 30 => false, 31 => false, 32 => false,
        33 => false, 34 => false, 35 => false, 36 => false, 37 => false, 38 => false,
        39 => false, 40 => false, 41 => false, 42 => false, 43 => false, 44 => false,
        45 => false, 46 => false, 47 => false, 48 => false, 49 => false, 50 => false,
        51 => false, 52 => false, 53 => false, 54 => false, 55 => false, 56 => false,
        57 => false, 58 => false, 59 => false, 60 => false, 61 => false, 62 => false,
        63 => true, 64 => false, 65 => false, 66 => false, 67 => false, 68 => false,
        69 => false, 70 => false, 71 => true, 72 => true, 73 => false, 74 => false,
        75 => false, 76 => true, 77 => false, 78 => false, 79 => false, 80 => false,
        81 => false, 82 => false, 83 => false, 84 => false, 85 => false, 86 => false,
        87 => false, 88 => false, 89 => false, 90 => false, 91 => false, 92 => false,
        93 => false, 94 => false, 95 => true, 96 => false, 97 => true, 98 => false,
        99 => false, 100 => false, 101 => false, 102 => false, 103 => false, 104 => false,
        105 => false, 106 => false, 107 => false, 108 => false, 109 => false, 110 => false,
        111 => false, 112 => false, 113 => true, 114 => false, 115 => false, 116 => false,
        117 => false, 118 => false, 119 => false, 120 => false, 121 => false, 122 => false,
        123 => false, 124 => false, 125 => false, 126 => false
    );

    const ADVANCED_UPDATES_DESCRIPTION = array(
        'seenOnAttributeAndObject' => array(
            'title' => 'First seen/Last seen Attribute table',
            'description' => 'Update the Attribute table to support first_seen and last_seen feature, with a microsecond resolution.',
            'liveOff' => true, # should the instance be offline for users other than site_admin
            'recommendBackup' => true, # should the update recommend backup
            'exitOnError' => false, # should the update exit on error
            'requirements' => 'MySQL version must be >= 5.6', # message stating the requirements necessary for the update
            'record' => false, # should the update success be saved in the admin_table
            // 'preUpdate' => 'seenOnAttributeAndObjectPreUpdate', # Function to execute before the update. If it throws an error, it cancels the update
            'url' => '/servers/updateDatabase/seenOnAttributeAndObject/' # url pointing to the funcion performing the update
        ),
    );

    public function __construct($id = false, $table = null, $ds = null)
    {
        parent::__construct($id, $table, $ds);
        $this->findMethods['column'] = true;
        if (in_array('phar', stream_get_wrappers(), true)) {
            stream_wrapper_unregister('phar');
        }
    }

    public function isAcceptedDatabaseError($errorMessage)
    {
        if ($this->isMysql()) {
            $errorDuplicateColumn = 'SQLSTATE[42S21]: Column already exists: 1060 Duplicate column name';
            $errorDuplicateIndex = 'SQLSTATE[42000]: Syntax error or access violation: 1061 Duplicate key name';
            $errorDropIndex = "/SQLSTATE\[42000\]: Syntax error or access violation: 1091 Can't DROP '[\w]+'; check that column\/key exists/";
            $isAccepted = substr($errorMessage, 0, strlen($errorDuplicateColumn)) === $errorDuplicateColumn ||
                            substr($errorMessage, 0, strlen($errorDuplicateIndex)) === $errorDuplicateIndex ||
                            preg_match($errorDropIndex, $errorMessage) !== 0;
        } else {
            $errorDuplicateColumn = '/ERROR:  column "[\w]+" specified more than once/';
            $errorDuplicateIndex = '/ERROR: relation "[\w]+" already exists/';
            $errorDropIndex = '/ERROR: index "[\w]+" does not exist/';
            $isAccepted = preg_match($errorDuplicateColumn, $errorMessage) !== 0 ||
                            preg_match($errorDuplicateIndex, $errorMessage) !== 0 ||
                            preg_match($errorDropIndex, $errorMessage) !== 0;
        }
        return $isAccepted;
    }

    // Generic update script
    // add special cases where the upgrade does more than just update the DB
    // this could become useful in the future
    public function updateMISP($command)
    {
        $dbUpdateSuccess = false;
        switch ($command) {
            case '2.4.20':
                $dbUpdateSuccess = $this->updateDatabase($command);
                //deprecated
                //$this->ShadowAttribute = ClassRegistry::init('ShadowAttribute');
                //$this->ShadowAttribute->upgradeToProposalCorrelation();
                break;
            case '2.4.25':
                $dbUpdateSuccess = $this->updateDatabase($command);
                $newFeeds = array(
                    array('provider' => 'CIRCL', 'name' => 'CIRCL OSINT Feed', 'url' => 'https://www.circl.lu/doc/misp/feed-osint', 'enabled' => 0),
                );
                $this->__addNewFeeds($newFeeds);
                break;
            case '2.4.27':
                $newFeeds = array(
                    array('provider' => 'Botvrij.eu', 'name' => 'The Botvrij.eu Data','url' => 'https://www.botvrij.eu/data/feed-osint', 'enabled' => 0)
                );
                $this->__addNewFeeds($newFeeds);
                break;
            case '2.4.49':
                $dbUpdateSuccess = $this->updateDatabase($command);
                $this->SharingGroup = ClassRegistry::init('SharingGroup');
                $this->SharingGroup->correctSyncedSharingGroups();
                $this->SharingGroup->updateRoaming();
                break;
            case '2.4.55':
                $dbUpdateSuccess = $this->updateDatabase('addSightings');
                break;
            case '2.4.66':
                $dbUpdateSuccess = $this->updateDatabase('2.4.66');
                $this->cleanCacheFiles();
                $this->Sighting = Classregistry::init('Sighting');
                $this->Sighting->addUuids();
                break;
            case '2.4.67':
                $dbUpdateSuccess = $this->updateDatabase('2.4.67');
                $this->Sighting = Classregistry::init('Sighting');
                $this->Sighting->addUuids();
                $this->Sighting->deleteAll(array('NOT' => array('Sighting.type' => array(0, 1, 2))));
                break;
            case '2.4.71':
                $this->OrgBlocklist = Classregistry::init('OrgBlocklist');
                $values = array(
                    array('org_uuid' => '58d38339-7b24-4386-b4b4-4c0f950d210f', 'org_name' => 'Setec Astrononomy', 'comment' => 'default example'),
                    array('org_uuid' => '58d38326-eda8-443a-9fa8-4e12950d210f', 'org_name' => 'Acme Finance', 'comment' => 'default example')
                );
                foreach ($values as $value) {
                    $found = $this->OrgBlocklist->find('first', array('conditions' => array('org_uuid' => $value['org_uuid']), 'recursive' => -1));
                    if (empty($found)) {
                        $this->OrgBlocklist->create();
                        $this->OrgBlocklist->save($value);
                    }
                }
                $dbUpdateSuccess = $this->updateDatabase($command);
                break;
            case '2.4.86':
                $this->MispObject = Classregistry::init('MispObject');
                $this->MispObject->removeOrphanedObjects();
                $dbUpdateSuccess = $this->updateDatabase($command);
                break;
            case 5:
                $dbUpdateSuccess = $this->updateDatabase($command);
                $this->Feed = Classregistry::init('Feed');
                $this->Feed->setEnableFeedCachingDefaults();
                break;
            case 8:
                $this->Server = Classregistry::init('Server');
                $this->Server->restartWorkers();
                break;
            case 10:
                $dbUpdateSuccess = $this->updateDatabase($command);
                $this->Role = Classregistry::init('Role');
                $this->Role->setPublishZmq();
                break;
            case 12:
                $this->__forceSettings();
                break;
            case 23:
                $this->__bumpReferences();
                break;
            case 34:
                $this->__fixServerPullPushRules();
                break;
            case 38:
                $dbUpdateSuccess = $this->updateDatabase($command);
                $this->__addServerPriority();
                break;
            case 46:
                $dbUpdateSuccess = $this->updateDatabase('seenOnAttributeAndObject');
                break;
            case 48:
                $dbUpdateSuccess = $this->__generateCorrelations();
                break;
            case 89:
                $this->__retireOldCorrelationEngine();
                $dbUpdateSuccess = true;
                break;
            case 90:
                $dbUpdateSuccess = $this->updateDatabase($command);
                $this->Workflow = Classregistry::init('Workflow');
                $this->Workflow->enableDefaultModules();
                break;
            case 91:
                $existing_index = $this->query(
                    "SHOW INDEX FROM default_correlations WHERE Key_name = 'unique_correlation';"
                );
                if (empty($existing_index)) {
                    // If there are duplicate entries, the query creating the `unique_correlation` index will result in an integrity constraint violation.
                    // The query below cleans up potential duplicates before creating the constraint.
                    $this->removeDuplicateCorrelationEntries('default_correlations');
                    $this->query(
                        "ALTER TABLE default_correlations
                        ADD CONSTRAINT unique_correlation
                        UNIQUE KEY(attribute_id, 1_attribute_id, value_id);"
                    );
                }
                $existing_index = $this->query(
                    "SHOW INDEX FROM no_acl_correlations WHERE Key_name = 'unique_correlation';"
                );
                if (empty($existing_index)) {
                    $this->removeDuplicateCorrelationEntries('no_acl_correlations');
                    $this->query(
                        "ALTER TABLE no_acl_correlations
                        ADD CONSTRAINT unique_correlation
                        UNIQUE KEY(attribute_id, 1_attribute_id, value_id);"
                    );
                }
                $dbUpdateSuccess = true;
                break;
            case 96:
                $this->removeDuplicatedUUIDs();
                $dbUpdateSuccess = $this->updateDatabase('createUUIDsConstraints');
                break;
            case 120:
                $dbUpdateSuccess = $this->moveImages();
                break;
            default:
                $dbUpdateSuccess = $this->updateDatabase($command);
                break;
        }
        return $dbUpdateSuccess;
    }

    private function __addServerPriority()
    {
        $this->Server = ClassRegistry::init('Server');
        $this->Server->reprioritise();
        return true;
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
        $this->Log->saveOrFailSilently($entry);
    }

    // SQL scripts for updates
    public function updateDatabase($command)
    {
        $this->Log = ClassRegistry::init('Log');

        $liveOff = false;
        $exitOnError = false;
        if (isset(self::ADVANCED_UPDATES_DESCRIPTION[$command])) {
            $liveOff = isset(self::ADVANCED_UPDATES_DESCRIPTION[$command]['liveOff']) ? self::ADVANCED_UPDATES_DESCRIPTION[$command]['liveOff'] : $liveOff;
            $exitOnError = isset(self::ADVANCED_UPDATES_DESCRIPTION[$command]['exitOnError']) ? self::ADVANCED_UPDATES_DESCRIPTION[$command]['exitOnError'] : $exitOnError;
        }

        $sqlArray = array();
        $indexArray = array();
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
            case 'x24betaupdates':
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
                if ($this->isMysql()) {
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
                } else {
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
            case 24:
                $this->GalaxyCluster = ClassRegistry::init('GalaxyCluster');
                if (empty($this->GalaxyCluster->schema('collection_uuid'))) {
                    $sqlArray[] = 'ALTER TABLE `galaxy_clusters` CHANGE `uuid` `collection_uuid` varchar(255) COLLATE utf8_bin NOT NULL;';
                    $sqlArray[] = 'ALTER TABLE `galaxy_clusters` ADD COLUMN `uuid` varchar(255) COLLATE utf8_bin NOT NULL default \'\';';
                }
                break;
            case 25:
                $this->__dropIndex('galaxy_clusters', 'uuid');
                $this->__addIndex('galaxy_clusters', 'uuid');
                $this->__addIndex('galaxy_clusters', 'collection_uuid');
                break;
            case 26:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS tag_collections (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `uuid` varchar(40) COLLATE utf8_bin DEFAULT NULL,
                    `user_id` int(11) NOT NULL,
                    `org_id` int(11) NOT NULL,
                    `name` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
                    `description` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
                    `all_orgs` tinyint(1) NOT NULL DEFAULT 0,
                    PRIMARY KEY (id),
                    INDEX `uuid` (`uuid`),
                    INDEX `user_id` (`user_id`),
                    INDEX `org_id` (`org_id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS tag_collection_tags (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `tag_collection_id` int(11) NOT NULL,
                    `tag_id` int(11) NOT NULL,
                    PRIMARY KEY (id),
                    INDEX `uuid` (`tag_collection_id`),
                    INDEX `user_id` (`tag_id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
                break;
            case 27:
                $sqlArray[] = 'ALTER TABLE `tags` CHANGE `org_id` `org_id` int(11) NOT NULL DEFAULT 0;';
                break;
            case 28:
                $sqlArray[] = "ALTER TABLE `servers` ADD `caching_enabled` tinyint(1) NOT NULL DEFAULT 0;";
                break;
            case 29:
                $sqlArray[] = "ALTER TABLE `galaxies` ADD `kill_chain_order` text NOT NULL;";
                break;
            case 30:
                $sqlArray[] = "ALTER TABLE `galaxies` MODIFY COLUMN `kill_chain_order` text";
                $sqlArray[] = "ALTER TABLE `feeds` ADD `force_to_ids` tinyint(1) NOT NULL DEFAULT 0;";
                break;
            case 31:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `rest_client_histories` (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `org_id` int(11) NOT NULL,
                    `user_id` int(11) NOT NULL,
                    `headers` text,
                    `body` text,
                    `url` text,
                    `http_method` varchar(255),
                    `timestamp` int(11) NOT NULL DEFAULT 0,
                    `use_full_path` tinyint(1) DEFAULT 0,
                    `show_result` tinyint(1) DEFAULT 0,
                    `skip_ssl` tinyint(1) DEFAULT 0,
                    `outcome` int(11) NOT NULL,
                    `bookmark` tinyint(1) NOT NULL DEFAUlT 0,
                    `bookmark_name` varchar(255) NULL DEFAULT '',
                    PRIMARY KEY (`id`),
                    KEY `org_id` (`org_id`),
                    KEY `user_id` (`user_id`),
                    KEY `timestamp` (`timestamp`)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
                break;
            case 32:
                $sqlArray[] = "ALTER TABLE `taxonomies` ADD `required` tinyint(1) NOT NULL DEFAULT 0;";
                break;
            case 33:
                $sqlArray[] = "ALTER TABLE `roles` ADD `perm_publish_kafka` tinyint(1) NOT NULL DEFAULT 0;";
                break;
            case 35:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `notification_logs` (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `org_id` int(11) NOT NULL,
                    `type` varchar(255) COLLATE utf8_bin NOT NULL,
                    `timestamp` int(11) NOT NULL DEFAULT 0,
                    PRIMARY KEY (`id`),
                    KEY `org_id` (`org_id`),
                    KEY `type` (`type`)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;";
                    break;
            case 36:
                $sqlArray[] = "ALTER TABLE `event_tags` ADD `local` tinyint(1) NOT NULL DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `attribute_tags` ADD `local` tinyint(1) NOT NULL DEFAULT 0;";
                break;
            case 37:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS decaying_models (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `uuid` varchar(40) COLLATE utf8_bin DEFAULT NULL,
                    `name` varchar(255) COLLATE utf8_bin NOT NULL,
                    `parameters` text,
                    `attribute_types` text,
                    `description` text,
                    `org_id` int(11),
                    `enabled` tinyint(1) NOT NULL DEFAULT 0,
                    `all_orgs` tinyint(1) NOT NULL DEFAULT 1,
                    `ref` text COLLATE utf8_unicode_ci,
                    `formula` varchar(255) COLLATE utf8_bin NOT NULL,
                    `version` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT '',
                    `default` tinyint(1) NOT NULL DEFAULT 0,
                    PRIMARY KEY (id),
                    INDEX `uuid` (`uuid`),
                    INDEX `name` (`name`),
                    INDEX `org_id` (`org_id`),
                    INDEX `enabled` (`enabled`),
                    INDEX `all_orgs` (`all_orgs`),
                    INDEX `version` (`version`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS decaying_model_mappings (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `attribute_type` varchar(255) COLLATE utf8_bin NOT NULL,
                    `model_id` int(11) NOT NULL,
                    PRIMARY KEY (id),
                    INDEX `model_id` (`model_id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
                $sqlArray[] = "ALTER TABLE `roles` ADD `perm_decaying` tinyint(1) NOT NULL DEFAULT 0;";
                $sqlArray[] = "UPDATE `roles` SET `perm_decaying`=1 WHERE `perm_sighting`=1;";
                break;
            case 38:
                $sqlArray[] = "ALTER TABLE servers ADD  priority int(11) NOT NULL DEFAULT 0;";
                $indexArray[] = array('servers', 'priority');
                break;
            case 39:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS user_settings (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `setting` varchar(255) COLLATE utf8_bin NOT NULL,
                    `value` text,
                    `user_id` int(11) NOT NULL,
                    `timestamp` int(11) NOT NULL,
                    PRIMARY KEY (id),
                    INDEX `key` (`key`),
                    INDEX `user_id` (`user_id`),
                    INDEX `timestamp` (`timestamp`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
                break;
            case 40:
                $sqlArray[] = "ALTER TABLE `user_settings` ADD `timestamp` int(11) NOT NULL;";
                $indexArray[] = array('user_settings', 'timestamp');
                break;
            case 41:
                $sqlArray[] = "ALTER TABLE `roles` ADD `enforce_rate_limit` tinyint(1) NOT NULL DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `roles` ADD `rate_limit_count` int(11) NOT NULL DEFAULT 0;";
                break;
            case 42:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS sightingdbs (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `name` varchar(255) NOT NULL,
                    `description` text,
                    `owner` varchar(255) DEFAULT '',
                    `host` varchar(255) DEFAULT 'http://localhost',
                    `port` int(11) DEFAULT 9999,
                    `timestamp` int(11) NOT NULL,
                    `enabled` tinyint(1) NOT NULL DEFAULT 0,
                    `skip_proxy` tinyint(1) NOT NULL DEFAULT 0,
                    `ssl_skip_verification` tinyint(1) NOT NULL DEFAULT 0,
                    PRIMARY KEY (id),
                    INDEX `name` (`name`),
                    INDEX `owner` (`owner`),
                    INDEX `host` (`host`),
                    INDEX `port` (`port`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS sightingdb_orgs (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `sightingdb_id` int(11) NOT NULL,
                    `org_id` int(11) NOT NULL,
                    PRIMARY KEY (id),
                    INDEX `sightingdb_id` (`sightingdb_id`),
                    INDEX `org_id` (`org_id`)
                ) ENGINE=InnoDB;";
                break;
            case 43:
                $sqlArray[] = "ALTER TABLE sightingdbs ADD namespace varchar(255) DEFAULT '';";
                break;
            case 44:
                $sqlArray[] = "ALTER TABLE object_template_elements CHANGE `disable_correlation` `disable_correlation` tinyint(1);";
                break;
            case 45:
                $sqlArray[] = "ALTER TABLE `events` ADD `sighting_timestamp` int(11) NOT NULL DEFAULT 0 AFTER `publish_timestamp`;";
                $sqlArray[] = "ALTER TABLE `servers` ADD `push_sightings` tinyint(1) NOT NULL DEFAULT 0 AFTER `pull`;";
                break;
            case 47:
                $this->__addIndex('tags', 'numerical_value');
                $this->__addIndex('taxonomy_predicates', 'numerical_value');
                $this->__addIndex('taxonomy_entries', 'numerical_value');
                break;
            case 49:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS dashboards (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `uuid` varchar(40) COLLATE utf8_bin NOT NULL,
                    `name` varchar(191) NOT NULL,
                    `description` text,
                    `default` tinyint(1) NOT NULL DEFAULT 0,
                    `selectable` tinyint(1) NOT NULL DEFAULT 0,
                    `user_id` int(11) NOT NULL DEFAULT 0,
                    `restrict_to_org_id` int(11) NOT NULL DEFAULT 0,
                    `restrict_to_role_id` int(11) NOT NULL DEFAULT 0,
                    `restrict_to_permission_flag` varchar(191) NOT NULL DEFAULT '',
                    `value` text,
                    `timestamp` int(11) NOT NULL,
                    PRIMARY KEY (id),
                    INDEX `name` (`name`),
                    INDEX `uuid` (`uuid`),
                    INDEX `user_id` (`user_id`),
                    INDEX `restrict_to_org_id` (`restrict_to_org_id`),
                    INDEX `restrict_to_permission_flag` (`restrict_to_permission_flag`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
                break;
            case 50:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS inbox (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `uuid` varchar(40) COLLATE utf8_bin NOT NULL,
                    `title` varchar(191) NOT NULL,
                    `type` varchar(191) NOT NULL,
                    `ip` varchar(191) NOT NULL,
                    `user_agent` text,
                    `user_agent_sha256` varchar(64) NOT NULL,
                    `comment` text,
                    `deleted` tinyint(1) NOT NULL DEFAULT 0,
                    `timestamp` int(11) NOT NULL,
                    `store_as_file` tinyint(1) NOT NULL DEFAULT 0,
                    `data` longtext,
                    PRIMARY KEY (id),
                    INDEX `title` (`title`),
                    INDEX `type` (`type`),
                    INDEX `uuid` (`uuid`),
                    INDEX `user_agent_sha256` (`user_agent_sha256`),
                    INDEX `ip` (`ip`),
                    INDEX `timestamp` (`timestamp`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
                break;
            case 51:
                $sqlArray[] = "ALTER TABLE `feeds` ADD `orgc_id` int(11) NOT NULL DEFAULT 0";
                $indexArray[] = array('feeds', 'orgc_id');
                break;
            case 52:
                if (!empty($this->query("SHOW COLUMNS FROM `admin_settings` LIKE 'key';"))) {
                    $sqlArray[] = "ALTER TABLE admin_settings CHANGE `key` `setting` varchar(255) COLLATE utf8_bin NOT NULL;";
                    $indexArray[] = array('admin_settings', 'setting');
                }
                break;
            case 53:
                if (!empty($this->query("SHOW COLUMNS FROM `user_settings` LIKE 'key';"))) {
                    $sqlArray[] = "ALTER TABLE user_settings CHANGE `key` `setting` varchar(255) COLLATE utf8_bin NOT NULL;";
                    $indexArray[] = array('user_settings', 'setting');
                }
                break;
            case 54:
                $sqlArray[] = "ALTER TABLE `sightingdbs` MODIFY `timestamp` int(11) NOT NULL DEFAULT 0;";
                break;
            case 55:
                // index is not used in any SQL query
                $this->__dropIndex('correlations', 'value');
                // these index can be theoretically used, but probably just in very rare occasion
                $this->__dropIndex('correlations', 'org_id');
                $this->__dropIndex('correlations', 'sharing_group_id');
                $this->__dropIndex('correlations', 'a_sharing_group_id');
                break;
            case 56:
                //rename tables
                $sqlArray[] = "RENAME TABLE `org_blacklists` TO `org_blocklists`;";
                $sqlArray[] = "RENAME TABLE `event_blacklists` TO `event_blocklists`;";
                $sqlArray[] = "RENAME TABLE `whitelist` TO `allowedlist`;";
                break;
            case 57:
                $sqlArray[] = sprintf("INSERT INTO `admin_settings` (`setting`, `value`) VALUES ('fix_login', %s);", time());
                break;
            case 58:
                $sqlArray[] = "ALTER TABLE `warninglists` MODIFY COLUMN `warninglist_entry_count` int(11) unsigned NOT NULL DEFAULT 0;";
                break;
            case 59:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS event_reports (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `uuid` varchar(40) COLLATE utf8_bin NOT NULL ,
                    `event_id` int(11) NOT NULL,
                    `name` varchar(255) NOT NULL,
                    `content` text,
                    `distribution` tinyint(4) NOT NULL DEFAULT 0,
                    `sharing_group_id` int(11),
                    `timestamp` int(11) NOT NULL,
                    `deleted` tinyint(1) NOT NULL DEFAULT 0,
                    PRIMARY KEY (id),
                    CONSTRAINT u_uuid UNIQUE (uuid),
                    INDEX `name` (`name`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
                break;
            case 60:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `attachment_scans` (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `type` varchar(40) COLLATE utf8_bin NOT NULL,
                    `attribute_id` int(11) NOT NULL,
                    `infected` tinyint(1) NOT NULL,
                    `malware_name`  varchar(191) NULL,
                    `timestamp` int(11) NOT NULL,
                    PRIMARY KEY (`id`),
                    INDEX `index` (`type`, `attribute_id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
                break;
            case 61:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `auth_keys` (
                    `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
                    `uuid` varchar(40) COLLATE utf8mb4_unicode_ci NOT NULL,
                    `authkey` varchar(72) CHARACTER SET ascii DEFAULT NULL,
                    `authkey_start` varchar(4) CHARACTER SET ascii DEFAULT NULL,
                    `authkey_end` varchar(4) CHARACTER SET ascii DEFAULT NULL,
                    `created` int(10) unsigned NOT NULL,
                    `expiration` int(10) unsigned NOT NULL,
                    `user_id` int(10) unsigned NOT NULL,
                    `comment` text COLLATE utf8mb4_unicode_ci,
                    PRIMARY KEY (`id`),
                    KEY `authkey_start` (`authkey_start`),
                    KEY `authkey_end` (`authkey_end`),
                    KEY `created` (`created`),
                    KEY `expiration` (`expiration`),
                    KEY `user_id` (`user_id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";
                break;
            case 62:
                $sqlArray[] = "ALTER TABLE `auth_keys` MODIFY COLUMN `authkey` varchar(72) CHARACTER SET ascii NOT NULL";
                $sqlArray[] = "ALTER TABLE `auth_keys` MODIFY COLUMN `authkey_start` varchar(4) CHARACTER SET ascii NOT NULL";
                $sqlArray[] = "ALTER TABLE `auth_keys` MODIFY COLUMN `authkey_end` varchar(4) CHARACTER SET ascii NOT NULL";
                $sqlArray[] = "ALTER TABLE `auth_keys` MODIFY COLUMN `comment` text COLLATE utf8mb4_unicode_ci";
                $sqlArray[] = "ALTER TABLE `attachment_scans` MODIFY COLUMN `malware_name` varchar(191) NULL";
                break;
            case 63:
                $sqlArray[] = "ALTER TABLE `galaxy_clusters` ADD `distribution` tinyint(4) NOT NULL DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `galaxy_clusters` ADD `sharing_group_id` int(11);";
                $sqlArray[] = "ALTER TABLE `galaxy_clusters` ADD `org_id` int(11) NOT NULL;";
                $sqlArray[] = "ALTER TABLE `galaxy_clusters` ADD `orgc_id` int(11) NOT NULL;";
                $sqlArray[] = "ALTER TABLE `galaxy_clusters` ADD `default` tinyint(1) NOT NULL DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `galaxy_clusters` ADD `locked` tinyint(1) NOT NULL DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `galaxy_clusters` ADD `extends_uuid` varchar(40) COLLATE utf8_bin DEFAULT '';";
                $sqlArray[] = "ALTER TABLE `galaxy_clusters` ADD `extends_version` int(11) DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `galaxy_clusters` ADD `published` tinyint(1) NOT NULL DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `galaxy_clusters` ADD `deleted` TINYINT(1) NOT NULL DEFAULT 0";
                $sqlArray[] = "ALTER TABLE `roles` ADD `perm_galaxy_editor` tinyint(1) NOT NULL DEFAULT 0;";

                $sqlArray[] = "UPDATE `roles` SET `perm_galaxy_editor`=1 WHERE `perm_tag_editor`=1;";
                $sqlArray[] = "UPDATE `galaxy_clusters` SET `distribution`=3, `default`=1 WHERE `org_id`=0;";

                $sqlArray[] = "ALTER TABLE `galaxy_reference` RENAME `galaxy_cluster_relations`;";
                $sqlArray[] = "ALTER TABLE `galaxy_cluster_relations` ADD `galaxy_cluster_uuid` varchar(40) COLLATE utf8_bin NOT NULL;";
                $sqlArray[] = "ALTER TABLE `galaxy_cluster_relations` ADD `distribution` tinyint(4) NOT NULL DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `galaxy_cluster_relations` ADD `sharing_group_id` int(11);";
                $sqlArray[] = "ALTER TABLE `galaxy_cluster_relations` ADD `default` tinyint(1) NOT NULL DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `galaxy_cluster_relations` DROP COLUMN `referenced_galaxy_cluster_value`;";
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `galaxy_cluster_relation_tags` (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `galaxy_cluster_relation_id` int(11) NOT NULL,
                    `tag_id` int(11) NOT NULL,
                    PRIMARY KEY (`id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8;";

                $sqlArray[] = "ALTER TABLE `tags` ADD `is_galaxy` tinyint(1) NOT NULL DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `tags` ADD `is_custom_galaxy` tinyint(1) NOT NULL DEFAULT 0;";
                $sqlArray[] = "UPDATE `tags` SET `is_galaxy`=1 WHERE `name` LIKE 'misp-galaxy:%';";
                $sqlArray[] = "UPDATE `tags` SET `is_custom_galaxy`=1 WHERE `name` REGEXP '^misp-galaxy:[^:=\"]+=\"[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\"$';";

                $sqlArray[] = "ALTER TABLE `servers` ADD `push_galaxy_clusters` tinyint(1) NOT NULL DEFAULT 0 AFTER `push_sightings`;";
                $sqlArray[] = "ALTER TABLE `servers` ADD `pull_galaxy_clusters` tinyint(1) NOT NULL DEFAULT 0 AFTER `push_galaxy_clusters`;";

                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `galaxy_cluster_blocklists` (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `cluster_uuid` varchar(40) COLLATE utf8_bin NOT NULL,
                    `created` datetime NOT NULL,
                    `cluster_info` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
                    `comment` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci,
                    `cluster_orgc` VARCHAR(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
                    PRIMARY KEY (`id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;";

                $indexArray[] = array('galaxy_clusters', 'org_id');
                $indexArray[] = array('galaxy_clusters', 'orgc_id');
                $indexArray[] = array('galaxy_clusters', 'sharing_group_id');
                $indexArray[] = array('galaxy_clusters', 'extends_uuid');
                $indexArray[] = array('galaxy_clusters', 'extends_version');
                $indexArray[] = array('galaxy_clusters', 'default');
                $indexArray[] = array('galaxy_cluster_relations', 'galaxy_cluster_uuid');
                $indexArray[] = array('galaxy_cluster_relations', 'sharing_group_id');
                $indexArray[] = array('galaxy_cluster_relations', 'default');
                $indexArray[] = array('galaxy_cluster_relation_tags', 'galaxy_cluster_relation_id');
                $indexArray[] = array('galaxy_cluster_relation_tags', 'tag_id');
                $indexArray[] = array('galaxy_cluster_blocklists', 'cluster_uuid');
                $indexArray[] = array('galaxy_cluster_blocklists', 'cluster_orgc');
                break;
            case 64:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `cerebrates` (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `name` varchar(191) NOT NULL,
                    `url` varchar(255) NOT NULL,
                    `authkey` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
                    `open` tinyint(1) DEFAULT 0,
                    `org_id` int(11) NOT NULL,
                    `pull_orgs` tinyint(1) DEFAULT 0,
                    `pull_sharing_groups` tinyint(1) DEFAULT 0,
                    `self_signed` tinyint(1) DEFAULT 0,
                    `cert_file` varchar(255) DEFAULT NULL,
                    `client_cert_file` varchar(255) DEFAULT NULL,
                    `internal` tinyint(1) NOT NULL DEFAULT 0,
                    `skip_proxy` tinyint(1) NOT NULL DEFAULT 0,
                    `description` text,
                    PRIMARY KEY (`id`),
                    KEY `url` (`url`),
                    KEY `org_id` (`org_id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";
                break;
            case 65:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `correlation_exclusions` (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `value` text NOT NULL,
                    `from_json` tinyint(1) default 0,
                    PRIMARY KEY (`id`),
                    UNIQUE INDEX `value` (`value`(191))
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";
                break;
            case 66:
                $sqlArray[] = "ALTER TABLE `galaxy_clusters` MODIFY COLUMN `tag_name` varchar(255) COLLATE utf8_unicode_ci NOT NULL DEFAULT '';";
                $indexArray[] = ['event_reports', 'event_id'];
                break;
            case 67:
                $sqlArray[] = "ALTER TABLE `auth_keys` ADD `allowed_ips` text DEFAULT NULL;";
                break;
            case 68:
                $sqlArray[] = "ALTER TABLE `correlation_exclusions` ADD `comment` text DEFAULT NULL;";
                break;
            case 69:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `audit_logs` (
                      `id` int(11) NOT NULL AUTO_INCREMENT,
                      `created` datetime NOT NULL,
                      `user_id` int(11) NOT NULL,
                      `org_id` int(11) NOT NULL,
                      `authkey_id` int(11) DEFAULT NULL,
                      `ip` varbinary(16) DEFAULT NULL,
                      `request_type` tinyint NOT NULL,
                      `request_id` varchar(255) DEFAULT NULL,
                      `action` varchar(20) NOT NULL,
                      `model` varchar(80) NOT NULL,
                      `model_id` int(11) NOT NULL,
                      `model_title` text DEFAULT NULL,
                      `event_id` int(11) NULL,
                      `change` blob,
                      PRIMARY KEY (`id`),
                      INDEX `event_id` (`event_id`),
                      INDEX `model_id` (`model_id`)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";
                break;
            case 70:
                $sqlArray[] = "ALTER TABLE `galaxies` ADD `enabled` tinyint(1) NOT NULL DEFAULT 1 AFTER `namespace`;";
                break;
            case 71:
                $sqlArray[] = "ALTER TABLE `roles` ADD `perm_warninglist` tinyint(1) NOT NULL DEFAULT 0;";
                $sqlArray[] = "ALTER TABLE `warninglist_entries` ADD `comment` text DEFAULT NULL;";
                $sqlArray[] = "ALTER TABLE `warninglists` ADD `default` tinyint(1) NOT NULL DEFAULT 1, ADD `category` varchar(20) NOT NULL DEFAULT 'false_positive', DROP COLUMN `warninglist_entry_count`";
                break;
            case 72:
                $sqlArray[] = "ALTER TABLE `auth_keys` ADD `read_only` tinyint(1) NOT NULL DEFAULT 0 AFTER `expiration`;";
                break;
            case 73:
                $this->__dropIndex('user_settings', 'timestamp'); // index is not used
                $sqlArray[] = "ALTER TABLE `user_settings` ADD UNIQUE INDEX `unique_setting` (`user_id`, `setting`)";
                break;
            case 74:
                $sqlArray[] = "ALTER TABLE `users` MODIFY COLUMN `change_pw` tinyint(1) NOT NULL DEFAULT 0;";
                break;
            case 75:
                $this->__addIndex('object_references', 'event_id');
                $this->__dropIndex('object_references', 'timestamp');
                $this->__dropIndex('object_references', 'source_uuid');
                $this->__dropIndex('object_references', 'relationship_type');
                $this->__dropIndex('object_references', 'referenced_uuid');
                break;
            case 76:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `system_settings` (
                      `setting` varchar(255) NOT NULL,
                      `value` blob NOT NULL,
                      PRIMARY KEY (`setting`)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";
                $sqlArray[] = "ALTER TABLE `servers` MODIFY COLUMN `authkey` VARBINARY(255) NOT NULL;";
                $sqlArray[] = "ALTER TABLE `cerebrates` MODIFY COLUMN `authkey` VARBINARY(255) NOT NULL;";
                break;
            case 77:
                $sqlArray[] = "ALTER TABLE `tags` ADD `local_only` tinyint(1) NOT NULL DEFAULT 0 AFTER `is_custom_galaxy`;";
                $sqlArray[] = "ALTER TABLE `galaxies` ADD `local_only` tinyint(1) NOT NULL DEFAULT 0 AFTER `enabled`;";
                break;
            case 78:
                $sqlArray[] = "ALTER TABLE `jobs` MODIFY COLUMN `process_id` varchar(36) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL;";
                break;
            case 79:
                $sqlArray[] = "ALTER TABLE `users` ADD `sub` varchar(255) NULL DEFAULT NULL;";
                $sqlArray[] = "ALTER TABLE `users` ADD UNIQUE INDEX `sub` (`sub`);";
                break;
            case 80:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `sharing_group_blueprints` (
                      `id` int(11) NOT NULL AUTO_INCREMENT,
                      `uuid` varchar(40) COLLATE utf8_bin NOT NULL ,
                      `name` varchar(191) NOT NULL,
                      `timestamp` int(11) NOT NULL DEFAULT 0,
                      `user_id` int(11) NOT NULL,
                      `org_id` int(11) NOT NULL,
                      `sharing_group_id` int(11),
                      `rules` text,
                      PRIMARY KEY (`id`),
                      INDEX `uuid` (`uuid`),
                      INDEX `name` (`name`),
                      INDEX `org_id` (`org_id`),
                      INDEX `sharing_group_id` (`sharing_group_id`)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";
                break;
            case 81:
                $fields = ['nationality', 'sector', 'type', 'name'];
                foreach ($fields as $field) {
                    $sqlArray[] = sprintf("UPDATE organisations SET %s = '' WHERE %s IS NULL;", $field, $field);
                    $sqlArray[] = sprintf("ALTER table organisations MODIFY %s varchar(255) NOT NULL DEFAULT '';", $field);
                }
                break;
            case 82:
                $sqlArray[] = sprintf("ALTER table organisations MODIFY description text;");
                break;
            case 83:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `sharing_group_blueprints` (
                      `id` int(11) NOT NULL AUTO_INCREMENT,
                      `uuid` varchar(40) COLLATE utf8_bin NOT NULL ,
                      `name` varchar(191) NOT NULL,
                      `timestamp` int(11) NOT NULL DEFAULT 0,
                      `user_id` int(11) NOT NULL,
                      `org_id` int(11) NOT NULL,
                      `sharing_group_id` int(11),
                      `rules` text,
                      PRIMARY KEY (`id`),
                      INDEX `uuid` (`uuid`),
                      INDEX `name` (`name`),
                      INDEX `org_id` (`org_id`),
                      INDEX `sharing_group_id` (`sharing_group_id`)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";
                break;
            case 84:
                $sqlArray[] = sprintf("ALTER table events add `protected` tinyint(1);");
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `cryptographic_keys` (
                      `id` int(11) NOT NULL AUTO_INCREMENT,
                      `uuid` varchar(40) COLLATE utf8_bin NOT NULL,
                      `type` varchar(40) COLLATE utf8_bin NOT NULL,
                      `timestamp` int(11) NOT NULL DEFAULT 0,
                      `parent_id` int(11) NOT NULL,
                      `parent_type` varchar(40) COLLATE utf8_bin NOT NULL,
                      `key_data` text,
                      `revoked` tinyint(1) NOT NULL DEFAULT 0,
                      `fingerprint` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT '',
                      PRIMARY KEY (`id`),
                      INDEX `uuid` (`uuid`),
                      INDEX `type` (`type`),
                      INDEX `parent_id` (`parent_id`)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";
                break;
            case 85:
                $this->__addIndex('cryptographic_keys', 'parent_type');
                $this->__addIndex('cryptographic_keys', 'fingerprint');
                break;
            case 86:
                $this->__addIndex('attributes', 'timestamp');
                break;
            case 87:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `no_acl_correlations` (
                    `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
                    `attribute_id` int(10) UNSIGNED NOT NULL,
                    `1_attribute_id` int(10) UNSIGNED NOT NULL,
                    `event_id` int(10) UNSIGNED NOT NULL,
                    `1_event_id` int(10) UNSIGNED NOT NULL,
                    `value_id` int(10) UNSIGNED NOT NULL,
                    PRIMARY KEY (`id`),
                    INDEX `event_id` (`event_id`),
                    INDEX `1_event_id` (`1_event_id`),
                    INDEX `attribute_id` (`attribute_id`),
                    INDEX `1_attribute_id` (`1_attribute_id`),
                    INDEX `value_id` (`value_id`)
                  ) ENGINE=InnoDB;";
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `default_correlations` (
                    `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
                    `attribute_id` int(10) UNSIGNED NOT NULL,
                    `object_id` int(10) UNSIGNED NOT NULL,
                    `event_id` int(10) UNSIGNED NOT NULL,
                    `org_id` int(10) UNSIGNED NOT NULL,
                    `distribution` tinyint(4) NOT NULL,
                    `object_distribution` tinyint(4) NOT NULL,
                    `event_distribution` tinyint(4) NOT NULL,
                    `sharing_group_id` int(10) UNSIGNED NOT NULL DEFAULT 0,
                    `object_sharing_group_id` int(10) UNSIGNED NOT NULL DEFAULT 0,
                    `event_sharing_group_id` int(10) UNSIGNED NOT NULL DEFAULT 0,
                    `1_attribute_id` int(10) UNSIGNED NOT NULL,
                    `1_object_id` int(10) UNSIGNED NOT NULL,
                    `1_event_id` int(10) UNSIGNED NOT NULL,
                    `1_org_id` int(10) UNSIGNED NOT NULL,
                    `1_distribution` tinyint(4) NOT NULL,
                    `1_object_distribution` tinyint(4) NOT NULL,
                    `1_event_distribution` tinyint(4) NOT NULL,
                    `1_sharing_group_id` int(10) UNSIGNED NOT NULL DEFAULT 0,
                    `1_object_sharing_group_id` int(10) UNSIGNED NOT NULL DEFAULT 0,
                    `1_event_sharing_group_id` int(10) UNSIGNED NOT NULL DEFAULT 0,
                    `value_id` int(10) UNSIGNED NOT NULL,
                    PRIMARY KEY (`id`),
                    INDEX `event_id` (`event_id`),
                    INDEX `attribute_id` (`attribute_id`),
                    INDEX `object_id` (`object_id`),
                    INDEX `org_id` (`org_id`),
                    INDEX `distribution` (`distribution`),
                    INDEX `object_distribution` (`object_distribution`),
                    INDEX `event_distribution` (`event_distribution`),
                    INDEX `sharing_group_id` (`sharing_group_id`),
                    INDEX `object_sharing_group_id` (`object_sharing_group_id`),
                    INDEX `event_sharing_group_id` (`event_sharing_group_id`),
                    INDEX `1_event_id` (`1_event_id`),
                    INDEX `1_attribute_id` (`1_attribute_id`),
                    INDEX `1_object_id` (`1_object_id`),
                    INDEX `1_org_id` (`1_org_id`),
                    INDEX `1_distribution` (`1_distribution`),
                    INDEX `1_object_distribution` (`1_object_distribution`),
                    INDEX `1_event_distribution` (`1_event_distribution`),
                    INDEX `1_sharing_group_id` (`1_sharing_group_id`),
                    INDEX `1_object_sharing_group_id` (`1_object_sharing_group_id`),
                    INDEX `1_event_sharing_group_id` (`1_event_sharing_group_id`),
                    INDEX `value_id` (`value_id`)
                  ) ENGINE=InnoDB;";
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `correlation_values` (
                    `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
                    `value` varchar(191) NOT NULL,
                    PRIMARY KEY (`id`),
                    UNIQUE KEY `value` (`value`(191))
                  ) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `over_correlating_values` (
                `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
                `value` text,
                `occurrence` int(10) UNSIGNED NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `value` (`value`(191)),
                INDEX `occurrence` (`occurrence`)
                ) ENGINE=InnoDB CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";
                break;
            case 88:
                $sqlArray[] = 'ALTER TABLE `users` ADD `external_auth_required` tinyint(1) NOT NULL DEFAULT 0;';
                $sqlArray[] = 'ALTER TABLE `users` ADD `external_auth_key` text COLLATE utf8_bin;';
                break;
            case 90:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `workflows` (
                      `id` int(11) NOT NULL AUTO_INCREMENT,
                      `uuid` varchar(40) COLLATE utf8_bin NOT NULL ,
                      `name` varchar(191) NOT NULL,
                      `description` varchar(191) NOT NULL,
                      `timestamp` int(11) NOT NULL DEFAULT 0,
                      `enabled` tinyint(1) NOT NULL DEFAULT 0,
                      `counter` int(11) NOT NULL DEFAULT 0,
                      `trigger_id` varchar(191) COLLATE utf8_bin NOT NULL,
                      `debug_enabled` tinyint(1) NOT NULL DEFAULT 0,
                      `data` text,
                      PRIMARY KEY (`id`),
                      INDEX `uuid` (`uuid`),
                      INDEX `name` (`name`),
                      INDEX `timestamp` (`timestamp`),
                      INDEX `trigger_id` (`trigger_id`)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `workflow_blueprints` (
                      `id` int(11) NOT NULL AUTO_INCREMENT,
                      `uuid` varchar(40) COLLATE utf8_bin NOT NULL ,
                      `name` varchar(191) NOT NULL,
                      `description` varchar(191) NOT NULL,
                      `timestamp` int(11) NOT NULL DEFAULT 0,
                      `default` tinyint(1) NOT NULL DEFAULT 0,
                      `data` text,
                      PRIMARY KEY (`id`),
                      INDEX `uuid` (`uuid`),
                      INDEX `name` (`name`),
                      INDEX `timestamp` (`timestamp`)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";
                    break;
            case 92:
                $sqlArray[] = "ALTER TABLE users ADD `last_api_access` INT(11) DEFAULT 0;";
                break;
            case 93:
                $this->__dropIndex('default_correlations', 'distribution');
                $this->__dropIndex('default_correlations', 'object_distribution');
                $this->__dropIndex('default_correlations', 'event_distribution');
                $this->__dropIndex('default_correlations', 'sharing_group_id');
                $this->__dropIndex('default_correlations', 'object_sharing_group_id');
                $this->__dropIndex('default_correlations', 'event_sharing_group_id');
                $this->__dropIndex('default_correlations', 'org_id');
                $this->__dropIndex('default_correlations', '1_distribution');
                $this->__dropIndex('default_correlations', '1_object_distribution');
                $this->__dropIndex('default_correlations', '1_event_distribution');
                $this->__dropIndex('default_correlations', '1_sharing_group_id');
                $this->__dropIndex('default_correlations', '1_object_sharing_group_id');
                $this->__dropIndex('default_correlations', '1_event_sharing_group_id');
                $this->__dropIndex('default_correlations', '1_org_id');
                break;
            case 94:
                $sqlArray[] = "UPDATE `over_correlating_values` SET `value` = SUBSTR(`value`, 1, 191);"; // truncate then migrate
                $sqlArray[] = "ALTER TABLE `over_correlating_values` MODIFY `value` varchar(191) NOT NULL;";
                break;
            case 95:
                $sqlArray[] = "ALTER TABLE `servers` ADD `remove_missing_tags` tinyint(1) NOT NULL DEFAULT 0 AFTER `skip_proxy`;";
                break;
            case 97:
                $sqlArray[] = "ALTER TABLE `users`
                    ADD COLUMN `notification_daily`     tinyint(1) NOT NULL DEFAULT 0,
                    ADD COLUMN `notification_weekly`    tinyint(1) NOT NULL DEFAULT 0,
                    ADD COLUMN `notification_monthly`   tinyint(1) NOT NULL DEFAULT 0
                ;";
                break;
            case 98:
                $this->__addIndex('object_template_elements', 'object_template_id');
                break;
            case 99: 
                $sqlArray[] = "ALTER TABLE `event_tags` ADD `relationship_type` varchar(191) NULL DEFAULT '';";
                $sqlArray[] = "ALTER TABLE `attribute_tags` ADD `relationship_type` varchar(191) NULL DEFAULT '';";
                break;
            case 100:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `access_logs` (
                  `id` int(11) NOT NULL AUTO_INCREMENT,
                  `created` datetime(4) NOT NULL,
                  `user_id` int(11) NOT NULL,
                  `org_id` int(11) NOT NULL,
                  `authkey_id` int(11) DEFAULT NULL,
                  `ip` varbinary(16) DEFAULT NULL,
                  `request_method` tinyint NOT NULL,
                  `user_agent` varchar(255) DEFAULT NULL,
                  `request_id` varchar(255) DEFAULT NULL,
                  `controller` varchar(20) NOT NULL,
                  `action` varchar(20) NOT NULL,
                  `url` varchar(255) NOT NULL,
                  `request` blob,
                  `response_code` smallint NOT NULL,  
                  `memory_usage` int(11) NOT NULL,
                  `duration` int(11) NOT NULL,
                  `query_count` int(11) NOT NULL,
                  PRIMARY KEY (`id`),
                  INDEX `user_id` (`user_id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";
                break;
            case 101:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `taxii_servers` (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `uuid` varchar(40) COLLATE utf8_bin NOT NULL ,
                    `name` varchar(191) NOT NULL,
                    `owner` varchar(191) NOT NULL,
                    `baseurl` varchar(191) NOT NULL,
                    `api_root` varchar(191) NOT NULL DEFAULT 0,
                    `description` text,
                    `filters` text,
                    `api_key` varchar(255)COLLATE utf8_bin NOT NULL,
                    PRIMARY KEY (`id`),
                    INDEX `uuid` (`uuid`),
                    INDEX `name` (`name`),
                    INDEX `baseurl` (`baseurl`)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";
                break;
            case 102:
                $sqlArray[] = "UPDATE roles SET perm_audit = 1;";
                break;
            case 103:
                $sqlArray[] = "ALTER TABLE `taxonomies` ADD `highlighted` tinyint(1) DEFAULT 0;";
                break;
            case 104:
                $sqlArray[] = "ALTER TABLE `access_logs` ADD `query_log` blob DEFAULT NULL";
                break;
            case 105:
                // set a default role if there is none
                if (!$this->AdminSetting->getSetting('default_role')) {
                    $role = ClassRegistry::init('Role')->findByName('User');
                    if ($role) {
                        $sqlArray[] = "INSERT INTO `admin_settings` (setting, value) VALUES ('default_role', '".$role['Role']['id']."');";
                    } else {
                        // there is no role called User, do nothing
                    }
                }
                break;
            case 106:
                $sqlArray[] = "ALTER TABLE `taxii_servers` MODIFY `baseurl` varchar(191) NOT NULL;";
                break;
            case 107:
                $sqlArray[] = "ALTER TABLE `auth_keys` ADD `unique_ips` text COLLATE utf8mb4_unicode_ci";
                break;
            case 108:
                $sqlArray[] = "ALTER TABLE `workflows` MODIFY `data` LONGTEXT;";
                break;
            case 109:
                $sqlArray[] = "UPDATE `over_correlating_values` SET `value` = LOWER(`value`) COLLATE utf8mb4_unicode_ci;";
                break;
            case 110:
                $sqlArray[] = "ALTER TABLE `users` ADD `totp` varchar(255) DEFAULT NULL;";
                $sqlArray[] = "ALTER TABLE `users` ADD `hotp_counter` int(11) DEFAULT NULL;";
                break;
            case 111:
                $sqlArray[] = "ALTER TABLE `taxii_servers` ADD `collection` varchar(40) CHARACTER SET ascii DEFAULT NULL;";
                break;
            case 112:
                $sqlArray[] = "ALTER TABLE `roles` ADD `perm_view_feed_correlations` tinyint(1) NOT NULL DEFAULT 0;";
                break;
            case 113:
                // we only want to update the existing roles - going forward the default is still 0
                // Also, we want to execute it as a separate update to ensure that cache clearing is done correctly
                $this->cleanCacheFiles();
                $sqlArray[] = "UPDATE roles SET perm_view_feed_correlations = 1;";
                break;
            case 114:
                $indexArray[] = ['object_references', 'uuid'];
                break;
            case 115:
                $sqlArray[] = "ALTER TABLE `users` ADD COLUMN `last_pw_change` BIGINT(20) NULL DEFAULT NULL;";
                $sqlArray[] = "UPDATE `users` SET last_pw_change=date_modified WHERE last_pw_change IS NULL";
                break;
            case 116:
                $sqlArray[] = "ALTER TABLE `event_reports` modify `content` mediumtext";
                break;
            case 117:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `user_login_profiles` (
                    `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
                    `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    `user_id` int(11) NOT NULL,
                    `status` varchar(191) DEFAULT NULL,
                    `ip` varchar(191) DEFAULT NULL,
                    `user_agent` varchar(191) DEFAULT NULL,
                    `accept_lang` varchar(191) DEFAULT NULL,
                    `geoip` varchar(191) DEFAULT NULL,
                    `ua_platform` varchar(191) DEFAULT NULL,
                    `ua_browser` varchar(191) DEFAULT NULL,
                    `ua_pattern` varchar(191) DEFAULT NULL,
                    `hash` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL,
                    PRIMARY KEY (`id`),
                    UNIQUE KEY `hash` (`hash`),
                    KEY `ip` (`ip`),
                    KEY `status` (`status`),
                    KEY `geoip` (`geoip`),
                    INDEX `user_id` (`user_id`)
                  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";
                break;
            case 118:
                $sqlArray[] = "ALTER TABLE `event_reports` MODIFY `content` mediumtext;";
                break;
            case 119:
                $sqlArray[] = "ALTER TABLE `access_logs` MODIFY `action` varchar(191) NOT NULL";
                break;
            case 121:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `notes` (
                    `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
                    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    `object_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    `object_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    `authors` text,
                    `org_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    `orgc_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    `created` datetime NOT NULL,
                    `modified` datetime NOT NULL,
                    `distribution` tinyint(4) NOT NULL,
                    `sharing_group_id` int(10) unsigned,
                    `locked` tinyint(1) NOT NULL DEFAULT 0,
                    `note` mediumtext,
                    `language` varchar(16) DEFAULT 'en',
                    PRIMARY KEY (`id`),
                    UNIQUE KEY `uuid` (`uuid`),
                    KEY `object_uuid` (`object_uuid`),
                    KEY `object_type` (`object_type`),
                    KEY `org_uuid` (`org_uuid`),
                    KEY `orgc_uuid` (`orgc_uuid`),
                    KEY `distribution` (`distribution`),
                    KEY `sharing_group_id` (`sharing_group_id`)
                  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `opinions` (
                    `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
                    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    `object_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    `object_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    `authors` text,
                    `org_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    `orgc_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    `created` datetime NOT NULL,
                    `modified` datetime NOT NULL,
                    `distribution` tinyint(4) NOT NULL,
                    `sharing_group_id` int(10) unsigned,
                    `locked` tinyint(1) NOT NULL DEFAULT 0,
                    `opinion` int(10) unsigned,
                    `comment` text,
                    PRIMARY KEY (`id`),
                    UNIQUE KEY `uuid` (`uuid`),
                    KEY `object_uuid` (`object_uuid`),
                    KEY `object_type` (`object_type`),
                    KEY `org_uuid` (`org_uuid`),
                    KEY `orgc_uuid` (`orgc_uuid`),
                    KEY `distribution` (`distribution`),
                    KEY `sharing_group_id` (`sharing_group_id`),
                    KEY `opinion` (`opinion`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `relationships` (
                    `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
                    `uuid` varchar(40) CHARACTER SET ascii NOT NULL,
                    `object_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    `object_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    `authors` text,
                    `org_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    `orgc_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    `created` datetime NOT NULL,
                    `modified` datetime NOT NULL,
                    `distribution` tinyint(4) NOT NULL,
                    `sharing_group_id` int(10) unsigned,
                    `locked` tinyint(1) NOT NULL DEFAULT 0,
                    `relationship_type` varchar(255) CHARACTER SET utf8 COLLATE utf8_unicode_ci,
                    `related_object_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    `related_object_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    PRIMARY KEY (`id`),
                    UNIQUE KEY `uuid` (`uuid`),
                    KEY `object_uuid` (`object_uuid`),
                    KEY `object_type` (`object_type`),
                    KEY `org_uuid` (`org_uuid`),
                    KEY `orgc_uuid` (`orgc_uuid`),
                    KEY `distribution` (`distribution`),
                    KEY `sharing_group_id` (`sharing_group_id`),
                    KEY `relationship_type` (`relationship_type`),
                    KEY `related_object_uuid` (`related_object_uuid`),
                    KEY `related_object_type` (`related_object_type`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `analyst_data_blocklists` (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `analyst_data_uuid` varchar(40) COLLATE utf8_bin NOT NULL,
                    `created` datetime NOT NULL,
                    `analyst_data_info` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
                    `comment` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci,
                    `analyst_data_orgc` VARCHAR(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
                    PRIMARY KEY (`id`),
                    KEY `analyst_data_uuid` (`analyst_data_uuid`),
                    KEY `analyst_data_orgc` (`analyst_data_orgc`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;";

                $sqlArray[] = "ALTER TABLE `roles` ADD `perm_analyst_data` tinyint(1) NOT NULL DEFAULT 0;";
                $sqlArray[] = "UPDATE `roles` SET `perm_analyst_data`=1 WHERE `perm_add` = 1;";

                $sqlArray[] = "ALTER TABLE `servers` ADD `push_analyst_data` tinyint(1) NOT NULL DEFAULT 0 AFTER `push_galaxy_clusters`;";
                $sqlArray[] = "ALTER TABLE `servers` ADD `pull_analyst_data` tinyint(1) NOT NULL DEFAULT 0 AFTER `push_analyst_data`;";
                break;
            case 122:
                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `collections` (
                    `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
                    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    `org_id` int(10) unsigned NOT NULL,
                    `orgc_id` int(10) unsigned NOT NULL,
                    `user_id` int(10) unsigned NOT NULL,
                    `created` datetime NOT NULL,
                    `modified` datetime NOT NULL,
                    `distribution` tinyint(4) NOT NULL,
                    `sharing_group_id` int(10) unsigned,
                    `name` varchar(191) NOT NULL,
                    `type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    `description` mediumtext,
                    PRIMARY KEY (`id`),
                    UNIQUE KEY `uuid` (`uuid`),
                    KEY `name` (`name`),
                    KEY `type` (`type`),
                    KEY `org_id` (`org_id`),
                    KEY `orgc_id` (`orgc_id`),
                    KEY `user_id` (`user_id`),
                    KEY `distribution` (`distribution`),
                    KEY `sharing_group_id` (`sharing_group_id`)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";

                $sqlArray[] = "CREATE TABLE IF NOT EXISTS `collection_elements` (
                    `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
                    `uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    `element_uuid` varchar(40) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    `element_type` varchar(80) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
                    `collection_id` int(10) unsigned NOT NULL,
                    `description` text,
                    PRIMARY KEY (`id`),
                    UNIQUE KEY `uuid` (`uuid`),
                    KEY `element_uuid` (`element_uuid`),
                    KEY `element_type` (`element_type`),
                    KEY `collection_id` (`collection_id`),
                    UNIQUE KEY `unique_element` (`element_uuid`, `collection_id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";
                break;
            case 123:
                $sqlArray[] = 'ALTER TABLE `notes` MODIFY `created` datetime NOT NULL';
                $sqlArray[] = 'ALTER TABLE `opinions` MODIFY `created` datetime NOT NULL;';
                $sqlArray[] = 'ALTER TABLE `relationships` MODIFY `created` datetime NOT NULL;';
                $sqlArray[] = 'ALTER TABLE `notes` MODIFY `modified` datetime NOT NULL;';
                $sqlArray[] = 'ALTER TABLE `opinions` MODIFY `modified` datetime NOT NULL;';
                $sqlArray[] = 'ALTER TABLE `relationships` MODIFY `modified` datetime NOT NULL;';
                break;
            case 124:
                $sqlArray[] = 'CREATE TABLE IF NOT EXISTS `sighting_blocklists` (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `org_uuid` varchar(40) COLLATE utf8_bin NOT NULL,
                    `created` datetime NOT NULL,
                    `org_name` varchar(255) COLLATE utf8_bin NOT NULL,
                    `comment` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci,
                    PRIMARY KEY (`id`),
                    INDEX `org_uuid` (`org_uuid`),
                    INDEX `org_name` (`org_name`)
                  ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;';
                break;
            case 125:
                $sqlArray[] = "ALTER TABLE `feeds` ADD COLUMN `tag_collection_id` INT(11) NOT NULL DEFAULT 0;";
                break;
            case 126:
                $sqlArray[] = "ALTER TABLE `roles` ADD `perm_skip_otp` tinyint(1) NOT NULL DEFAULT 0;";
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
            case 'seenOnAttributeAndObject':
                $sqlArray[] =
                    "ALTER TABLE `attributes`
                        DROP INDEX uuid,
                        DROP INDEX event_id,
                        DROP INDEX sharing_group_id,
                        DROP INDEX type,
                        DROP INDEX category,
                        DROP INDEX value1,
                        DROP INDEX value2,
                        DROP INDEX object_id,
                        DROP INDEX object_relation;
                    ";
                $sqlArray[] = "ALTER TABLE `attributes` DROP INDEX deleted"; // deleted index may not be present
                $sqlArray[] = "ALTER TABLE `attributes` DROP INDEX comment"; // for replayability
                $sqlArray[] = "ALTER TABLE `attributes` DROP INDEX first_seen"; // for replayability
                $sqlArray[] = "ALTER TABLE `attributes` DROP INDEX last_seen"; // for replayability
                $sqlArray[] =
                    "ALTER TABLE `attributes`
                        ADD COLUMN `first_seen` BIGINT(20) NULL DEFAULT NULL,
                        ADD COLUMN `last_seen` BIGINT(20) NULL DEFAULT NULL,
                        MODIFY comment TEXT COLLATE utf8_unicode_ci
                    ;";
                $indexArray[] = array('attributes', 'uuid');
                $indexArray[] = array('attributes', 'event_id');
                $indexArray[] = array('attributes', 'sharing_group_id');
                $indexArray[] = array('attributes', 'type');
                $indexArray[] = array('attributes', 'category');
                $indexArray[] = array('attributes', 'value1', 255);
                $indexArray[] = array('attributes', 'value2', 255);
                $indexArray[] = array('attributes', 'object_id');
                $indexArray[] = array('attributes', 'object_relation');
                $indexArray[] = array('attributes', 'deleted');
                $indexArray[] = array('attributes', 'first_seen');
                $indexArray[] = array('attributes', 'last_seen');
                $sqlArray[] = "
                    ALTER TABLE `objects`
                        ADD `first_seen` BIGINT(20) NULL DEFAULT NULL,
                        ADD `last_seen` BIGINT(20) NULL DEFAULT NULL,
                        MODIFY comment TEXT COLLATE utf8_unicode_ci
                    ;";
                $indexArray[] = array('objects', 'first_seen');
                $indexArray[] = array('objects', 'last_seen');
                $sqlArray[] = "
                    ALTER TABLE `shadow_attributes`
                        ADD `first_seen` BIGINT(20) NULL DEFAULT NULL,
                        ADD `last_seen` BIGINT(20) NULL DEFAULT NULL,
                        MODIFY comment TEXT COLLATE utf8_unicode_ci
                    ;";
                $indexArray[] = array('shadow_attributes', 'first_seen');
                $indexArray[] = array('shadow_attributes', 'last_seen');
                break;
            case 'createUUIDsConstraints':
                $tables_to_check = ['events', 'attributes', 'objects', 'sightings', 'dashboards', 'inbox', 'organisations', 'tag_collections'];
                foreach ($tables_to_check as $table) {
                    if (!$this->__checkIndexExists($table, 'uuid', true)) {
                        $this->__dropIndex($table, 'uuid');
                        $this->__addIndex($table, 'uuid', null, true);
                    }
                }
                break;
            default:
                return false;
        }

        // switch MISP instance live to false
        if ($liveOff) {
            $this->setLive(false);
        }
        $sql_update_count = count($sqlArray);
        $index_update_count = count($indexArray);
        $total_update_count = $sql_update_count + $index_update_count;
        $this->__setUpdateProgress(0, $total_update_count, $command);
        $str_index_array = array();
        foreach ($indexArray as $toIndex) {
            $str_index_array[] = __('Indexing %s -> %s', $toIndex[0], $toIndex[1]);
        }
        $this->__setUpdateCmdMessages(array_merge($sqlArray, $str_index_array));
        $flagStop = false;
        $errorCount = 0;

        // execute test before update. Exit if it fails
        if (isset(self::ADVANCED_UPDATES_DESCRIPTION[$command]['preUpdate'])) {
            $function_name = self::ADVANCED_UPDATES_DESCRIPTION[$command]['preUpdate'];
            try {
                $this->{$function_name}();
            } catch (Exception $e) {
                $this->__setPreUpdateTestState(false);
                $this->__setUpdateProgress(0, false);
                $this->__setUpdateResMessages(0, __('Issues executing the pre-update test `%s`. The returned error is: %s', $function_name, $e->getMessage()) . PHP_EOL);
                $this->__setUpdateError(0);
                $errorCount++;
                $exitOnError = true;
                $flagStop = true;
            }
        }

        if (!$flagStop) {
            $this->__setPreUpdateTestState(true);
            foreach ($sqlArray as $i => $sql) {
                try {
                    $this->__setUpdateProgress($i, false);
                    $this->query($sql);
                    $this->Log->create();
                    $this->Log->saveOrFailSilently(array(
                        'org' => 'SYSTEM',
                        'model' => 'Server',
                        'model_id' => 0,
                        'email' => 'SYSTEM',
                        'action' => 'update_database',
                        'user_id' => 0,
                        'title' => __('Successfully executed the SQL query for ') . $command,
                        'change' => __('The executed SQL query was: %s', $sql),
                    ));
                    $this->__setUpdateResMessages($i, __('Successfully executed the SQL query for %s', $command));
                } catch (Exception $e) {
                    $errorMessage = $e->getMessage();
                    $this->Log->create();
                    $logMessage = array(
                        'org' => 'SYSTEM',
                        'model' => 'Server',
                        'model_id' => 0,
                        'email' => 'SYSTEM',
                        'action' => 'update_database',
                        'user_id' => 0,
                        'title' => __('Issues executing the SQL query for %s', $command),
                        'change' => __('The executed SQL query was: ') . $sql . PHP_EOL . __(' The returned error is: ') . $errorMessage
                    );
                    $this->__setUpdateResMessages($i, __('Issues executing the SQL query for `%s`. The returned error is: ' . PHP_EOL . '%s', $command, $errorMessage));
                    if (!$this->isAcceptedDatabaseError($errorMessage)) {
                        $this->__setUpdateError($i);
                        $errorCount++;
                        if ($exitOnError) {
                            $flagStop = true;
                            break;
                        }
                    } else {
                        $logMessage['change'] = $logMessage['change'] . PHP_EOL . __('However, as this error is allowed, the update went through.');
                    }
                    $this->Log->saveOrFailSilently($logMessage);
                }
            }
        }
        if (!$flagStop) {
            if (!empty($indexArray)) {
                if ($clean) {
                    $this->cleanCacheFiles();
                }
                foreach ($indexArray as $i => $iA) {
                    $this->__setUpdateProgress(count($sqlArray)+$i, false);
                    if (isset($iA[2])) {
                        $indexSuccess = $this->__addIndex($iA[0], $iA[1], $iA[2]);
                    } else {
                        $indexSuccess = $this->__addIndex($iA[0], $iA[1]);
                    }
                    if ($indexSuccess['success']) {
                        $this->__setUpdateResMessages(count($sqlArray)+$i, __('Successfully indexed %s -> %s', $iA[0], $iA[1]));
                    } else {
                        $this->__setUpdateResMessages(count($sqlArray)+$i, sprintf('%s %s %s %s',
                            __('Failed to add index'),
                            sprintf('%s -> %s', $iA[0], $iA[1]),
                            __('The returned error is:') . PHP_EOL,
                            $indexSuccess['errorMessage']
                        ));
                        $this->__setUpdateError(count($sqlArray)+$i);
                    }
                }
            }
            $this->__setUpdateProgress(count($sqlArray) + count($indexArray), false);
         }
        if ($clean) {
            $this->cleanCacheFiles();
        }
        if ($liveOff) {
            $this->setLive(true);
        }
        if (!$flagStop && $errorCount == 0) {
            $this->__postUpdate($command);
        }
        if ($flagStop && $errorCount > 0) {
            $this->Log->create();
            $this->Log->saveOrFailSilently(array(
                'org' => 'SYSTEM',
                'model' => 'Server',
                'model_id' => 0,
                'email' => 'SYSTEM',
                'action' => 'update_database',
                'user_id' => 0,
                'title' => __('Issues executing the SQL query for %s', $command),
                'change' => __('Database updates stopped as some errors occurred and the stop flag is enabled.')
            ));
            return false;
        }
        return true;
    }

    /**
     * Set if misp is live in redis or in config file as fallback
     * @param bool $isLive
     */
    private function setLive($isLive)
    {
        try {
            $redis = $this->setupRedisWithException();
            if ($isLive) {
                $redis->del('misp:live');
            } else {
                $redis->set('misp:live', '0');
            }
        } catch (Exception $e) {
            // pass
        }

        if (!isset($this->Server)) {
            $this->Server = ClassRegistry::init('Server');
        }
        $this->Server->serverSettingsSaveValue('MISP.live', $isLive);
    }

    /**
     * Check whether the adminSetting should be updated after the update.
     * @param string $command
     * @return void
     */
    private function __postUpdate($command)
    {
        if (isset(self::ADVANCED_UPDATES_DESCRIPTION[$command]['record'])) {
            if (self::ADVANCED_UPDATES_DESCRIPTION[$command]['record']) {
                $this->AdminSetting->changeSetting($command, 1);
            }
        }
    }

    private function __dropIndex($table, $field)
    {
        $this->Log = ClassRegistry::init('Log');
        $indexCheckResult = array();
        if ($this->isMysql()) {
            $indexCheck = "SELECT INDEX_NAME FROM INFORMATION_SCHEMA.STATISTICS WHERE table_schema=DATABASE() AND table_name='" . $table . "' AND index_name LIKE '" . $field . "%';";
            $indexCheckResult = $this->query($indexCheck);
        } else {
            $pgIndexName = 'idx_' . $table . '_' . $field;
            $indexCheckResult[] = array('STATISTICS' => array('INDEX_NAME' => $pgIndexName));
        }
        foreach ($indexCheckResult as $icr) {
            if ($this->isMysql()) {
                $dropIndex = 'ALTER TABLE ' . $table . ' DROP INDEX ' . $icr['STATISTICS']['INDEX_NAME'] . ';';
            } else {
                $dropIndex = 'DROP INDEX IF EXISTS ' . $icr['STATISTICS']['INDEX_NAME'] . ';';
            }
            $result = true;
            try {
                $this->query($dropIndex);
            } catch (Exception $e) {
                $result = false;
            }
            $this->Log->create();
            $this->Log->saveOrFailSilently(array(
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

    private function __addIndex($table, $field, $length = null, $unique = false)
    {
        $this->Log = ClassRegistry::init('Log');
        $index = $unique ? 'UNIQUE INDEX' : 'INDEX';
        if (!$this->isMysql()) {
            $addIndex = "CREATE $index idx_" . $table . "_" . $field . " ON " . $table . " (" . $field . ");";
        } else {
            if (!$length) {
                $addIndex = "ALTER TABLE `" . $table . "` ADD $index `" . $field . "` (`" . $field . "`);";
            } else {
                $addIndex = "ALTER TABLE `" . $table . "` ADD $index `" . $field . "` (`" . $field . "`(" . $length . "));";
            }
        }
        $result = true;
        $duplicate = false;
        $errorMessage = '';
        try {
            $this->query($addIndex);
        } catch (Exception $e) {
            $duplicate = strpos($e->getMessage(), '1061') !== false;
            $errorMessage = $e->getMessage();
            $result = false;
        }
        $this->Log->create();
        $this->Log->saveOrFailSilently(array(
            'org' => 'SYSTEM',
            'model' => 'Server',
            'model_id' => 0,
            'email' => 'SYSTEM',
            'action' => 'update_database',
            'user_id' => 0,
            'title' => ($result ? 'Added index ' : 'Failed to add index ') . $field . ' to ' . $table . ($duplicate ? ' (index already set)' : $errorMessage),
            'change' => ($result ? 'Added index ' : 'Failed to add index ') . $field . ' to ' . $table . ($duplicate ? ' (index already set)' : $errorMessage),
        ));
        $additionResult = array('success' => $result || $duplicate);
        if (!$result) {
            $additionResult['errorMessage'] = $errorMessage;
        }
        return $additionResult;
    }

    private function __checkIndexExists($table, $column_name, $is_unique = false): bool
    {
        $query = sprintf(
            'SHOW INDEX FROM %s WHERE Column_name = \'%s\' and Non_unique = %s;',
            $table,
            $column_name,
            !empty($is_unique) ? '0' : '1'
        );
        $existing_index = $this->query($query);
        return !empty($existing_index);
    }

    public function cleanCacheFiles()
    {
        Cache::clear();
        Cache::clear(false, '_cake_core_');
        Cache::clear(false, '_cake_model_');
        clearCache();

        $files = glob(CACHE . 'models' . DS . 'myapp*');
        $files = array_merge($files, glob(CACHE . 'persistent' . DS . 'myapp*'));
        foreach ($files as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }
        return true;
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
    public function valueNotEmpty(array $value)
    {
        $field = array_key_first($value);
        $value = trim($value[$field]);
        if (!empty($value)) {
            return true;
        }
        return ucfirst($field) . ' cannot be empty.';
    }

    public function valueIsJson(array $value)
    {
        $value = current($value);
        if (!JsonTool::isValid($value)) {
            return __('Invalid JSON.');
        }
        return true;
    }

    public function valueIsID(array $value)
    {
        $field = array_key_first($value);
        if (!is_numeric($value[$field]) || $value[$field] < 0) {
            return 'Invalid ' . ucfirst($field) . ' ID';
        }
        return true;
    }

    public function stringNotEmpty(array $value)
    {
        $field = array_key_first($value);
        $value = trim($value[$field]);
        if (!isset($value) || ($value == false && $value !== "0")) {
            return ucfirst($field) . ' cannot be empty.';
        }
        return true;
    }

    // Try to create a table with a BIGINT(20)
    public function seenOnAttributeAndObjectPreUpdate()
    {
        $sqlArray[] = "CREATE TABLE IF NOT EXISTS testtable (
            `testfield` BIGINT(6) NULL DEFAULT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
        try {
            foreach($sqlArray as $i => $sql) {
                $this->query($sql);
            }
        } catch (Exception $e) {
            throw new Exception('Pre update test failed: ' . PHP_EOL . $sql . PHP_EOL . ' The returned error is: ' . $e->getMessage());
        }
        // clean up
        $sqlArray[] = "DROP TABLE testtable;";
        foreach($sqlArray as $i => $sql) {
            $this->query($sql);
        }
    }

    public function runUpdates($verbose = false, $useWorker = true, $processId = false)
    {
        $this->AdminSetting = ClassRegistry::init('AdminSetting');
        $this->Job = ClassRegistry::init('Job');

        $db = ConnectionManager::getDataSource('default');
        $tables = $db->listSources();
        $requiresLogout = false;
        // if we don't even have an admin table, time to create it.
        if (!in_array('admin_settings', $tables, true)) {
            $this->updateDatabase('adminTable');
            $requiresLogout = true;
        } else {
            $this->__runCleanDB();
            $db_version = $this->AdminSetting->find('all', [
                'conditions' => array('setting' => 'db_version'),
                'fields' => ['id', 'value'],
            ]);
            if (count($db_version) > 1) {
                // we ran into a bug where we have more than one db_version entry. This bug happened in some rare circumstances around 2.4.50-2.4.57
                foreach ($db_version as $k => $v) {
                    if ($k > 0) {
                        $this->AdminSetting->delete($v['AdminSetting']['id']);
                    }
                }
            }
            $db_version = $db_version[0];
            $updates = $this->findUpgrades($db_version['AdminSetting']['value']);
            if ($processId) {
                $job = $this->Job->find('first', array(
                    'conditions' => array('Job.id' => $processId)
                ));
            } else {
                $job = null;
            }
            if (!empty($updates)) {
                $this->Log = ClassRegistry::init('Log');
                $this->Server = ClassRegistry::init('Server');
                // Exit if updates are locked.
                // This is not as reliable as a real lock implementation
                // However, as all updates are re-playable, there is no harm if they
                // get played multiple time. The purpose of this lightweight lock
                // is only to limit the load.
                if ($this->isUpdateLocked()) { // prevent creation of useless workers
                    $this->Log->create();
                    $this->Log->saveOrFailSilently(array(
                        'org' => 'SYSTEM',
                        'model' => 'Server',
                        'model_id' => 0,
                        'email' => 'SYSTEM',
                        'action' => 'update_db_worker',
                        'user_id' => 0,
                        'title' => __('Issues executing run_updates'),
                        'change' => __('Database updates are locked. Make sure that you have an update worker running. If you do, it might be related to an update\'s execution repeatedly failing or still being in progress.')
                    ));
                    if (!empty($job)) { // if multiple prio worker is enabled, want to mark them as done
                        $job['Job']['progress'] = 100;
                        $job['Job']['message'] = __('Update done');
                       $this->Job->save($job);
                    }
                    return true;
                }

                // restart this function by a worker
                if ($useWorker && Configure::read('MISP.background_jobs')) {
                    $workerIssueCount = 0;
                    $workerDiagnostic = $this->Server->workerDiagnostics($workerIssueCount);
                    if (isset($workerDiagnostic['update']['ok']) && $workerDiagnostic['update']['ok']) {
                        $workerType = 'update';
                    } else { // update worker not running, doing the update inline
                        return $this->runUpdates($verbose, false);
                    }

                    /** @var Job $job */
                    $job = ClassRegistry::init('Job');
                    $jobId = $job->createJob(
                            'SYSTEM',
                            Job::WORKER_UPDATE,
                            'run_updates',
                            'command: ' . implode(',', $updates),
                            'Updating.'
                        );

                    $this->getBackgroundJobsTool()->enqueue(
                        BackgroundJobsTool::UPDATE_QUEUE,
                        BackgroundJobsTool::CMD_ADMIN,
                        [
                            'runUpdates',
                            $jobId
                        ],
                        true,
                        $jobId
                    );

                    return true;
                }

                // See comment above for `isUpdateLocked()`
                // prevent continuation of job if worker was already spawned
                // (could happens if multiple prio workers are up)
                if ($this->isUpdateLocked()) {
                    $this->Log->create();
                    $this->Log->saveOrFailSilently(array(
                        'org' => 'SYSTEM',
                        'model' => 'Server',
                        'model_id' => 0,
                        'email' => 'SYSTEM',
                        'action' => 'update_db_worker',
                        'user_id' => 0,
                        'title' => __('Issues executing run_updates'),
                        'change' => __('Updates are locked. Stopping worker gracefully')
                    ));
                    if (!empty($job)) {
                        $job['Job']['progress'] = 100;
                        $job['Job']['message'] = __('Update done');
                        $this->Job->save($job);
                    }
                    return true;
                }
                $this->changeLockState(time());
                $this->__resetUpdateProgress();

                $update_done = 0;
                foreach ($updates as $update => $temp) {
                    if ($verbose) {
                        echo str_pad('Executing ' . $update, 30, '.');
                    }
                    if (!empty($job)) {
                        $job['Job']['progress'] = floor($update_done / count($updates) * 100);
                        $job['Job']['message'] = __('Running update %s', $update);
                        $this->Job->save($job);
                    }
                    $dbUpdateSuccess = $this->updateMISP($update);
                    if ($temp) {
                        $requiresLogout = true;
                    }
                    if ($dbUpdateSuccess) {
                        $db_version['AdminSetting']['value'] = $update;
                        $this->AdminSetting->save($db_version);
                        $this->resetUpdateFailNumber();
                    } else {
                        $this->__increaseUpdateFailNumber();
                    }
                    if ($verbose) {
                        echo "\033[32mDone\033[0m" . PHP_EOL;
                    }
                    $update_done++;
                }
                if (!empty($job)) {
                    $job['Job']['message'] = __('Update done');
                }
                $this->changeLockState(false);
                $this->__queueCleanDB();
            } else {
                if (!empty($job)) {
                    $job['Job']['message'] = __('Update done in another worker. Gracefully stopping.');
                }
            }
            // mark current worker as done, as well as queued workers than manages to pass the locks
            // (happens if user hit reload before first worker start its job)
            if (!empty($job)) {
                $job['Job']['progress'] = 100;
                $this->Job->save($job);
            }
        }
        if ($requiresLogout) {
            $this->refreshSessions();
        }
        return true;
    }

    /**
     * Update date_modified for all users, this will ensure that all users will refresh their session data.
     */
    private function refreshSessions()
    {
        $this->User = ClassRegistry::init('User');
        $this->User->updateAll(['date_modified' => time()]);
    }

    private function __setUpdateProgress($current, $total=false, $toward_db_version=false)
    {
        $updateProgress = $this->getUpdateProgress();
        $updateProgress['current'] = $current;
        if ($total !== false) {
            $updateProgress['total'] = $total;
        } else {
            $now = new DateTime();
            $updateProgress['time']['started'][$current] = $now->format('Y-m-d H:i:s');
        }
        if ($toward_db_version !== false) {
            $updateProgress['toward_db_version'] = $toward_db_version;
        }
        $this->__saveUpdateProgress($updateProgress);
    }

    private function __setPreUpdateTestState($state)
    {
        $updateProgress = $this->getUpdateProgress();
        $updateProgress['preTestSuccess'] = $state;
        $this->__saveUpdateProgress($updateProgress);
    }

    private function __setUpdateError($index)
    {
        $updateProgress = $this->getUpdateProgress();
        $updateProgress['failed_num'][] = $index;
        $this->__saveUpdateProgress($updateProgress);
    }

    private function __getEmptyUpdateMessage()
    {
        return array(
            'commands' => array(),
            'results' => array(),
            'time' => array('started' => array(), 'elapsed' => array()),
            'current' => '',
            'total' => '',
            'failed_num' => array(),
            'toward_db_version' => ''
        );
    }

    private function __resetUpdateProgress()
    {
        $updateProgress = $this->__getEmptyUpdateMessage();
        $this->__saveUpdateProgress($updateProgress);
    }

    private function __setUpdateCmdMessages($messages)
    {
        $updateProgress = $this->getUpdateProgress();
        $updateProgress['commands'] = $messages;
        $this->__saveUpdateProgress($updateProgress);
    }

    private function __setUpdateResMessages($index, $message)
    {
        $updateProgress = $this->getUpdateProgress();
        $updateProgress['results'][$index] = $message;
        $temp = new DateTime();
        $diff = $temp->diff(new DateTime($updateProgress['time']['started'][$index]));
        $updateProgress['time']['elapsed'][$index] = $diff->format('%H:%I:%S');
        $this->__saveUpdateProgress($updateProgress);
    }

    public function getUpdateProgress()
    {
        if (!isset($this->AdminSetting)) {
            $this->AdminSetting = ClassRegistry::init('AdminSetting');
        }
        $updateProgress = $this->AdminSetting->getSetting('update_progress');
        if ($updateProgress !== false) {
            $updateProgress = json_decode($updateProgress, true);
        } else {
            $updateProgress = $this->__getEmptyUpdateMessage();
        }
        foreach($updateProgress as $setting => $value) {
            if (!is_array($value)) {
                if (is_numeric($value)) {
                    $value = intval($value);
                }
            }
            $updateProgress[$setting] = $value;
        }
        return $updateProgress;
    }

    private function __saveUpdateProgress($updateProgress)
    {
        if (!isset($this->AdminSetting)) {
            $this->AdminSetting = ClassRegistry::init('AdminSetting');
        }
        $data = json_encode($updateProgress);
        $this->AdminSetting->changeSetting('update_progress', $data);
    }

    public function changeLockState($locked)
    {
        if (!isset($this->AdminSetting)) {
            $this->AdminSetting = ClassRegistry::init('AdminSetting');
        }
        $this->AdminSetting->changeSetting('update_locked', $locked);
    }

    private function getUpdateLockState()
    {
        if (!isset($this->AdminSetting)) {
            $this->AdminSetting = ClassRegistry::init('AdminSetting');
        }
        $locked = $this->AdminSetting->getSetting('update_locked');
        return is_null($locked) ? false : $locked;
    }

    public function getLockRemainingTime()
    {
        $lockState = $this->getUpdateLockState();
        if ($lockState !== false && $lockState !== '') {
            // if lock is old, still allows the update
            // This can be useful if the update process crashes
            $diffSec = time() - intval($lockState);
            if (Configure::read('MISP.updateTimeThreshold')) {
                $updateWaitThreshold = intval(Configure::read('MISP.updateTimeThreshold'));
            } else {
                $this->Server = ClassRegistry::init('Server');
                $updateWaitThreshold = intval($this->Server->serverSettings['MISP']['updateTimeThreshold']['value']);
            }
            $remainingTime = $updateWaitThreshold - $diffSec;
            return $remainingTime > 0 ? $remainingTime : 0;
        } else {
            return 0;
        }
    }

    public function isUpdateLocked()
    {
        $remainingTime = $this->getLockRemainingTime();
        $failThresholdReached = $this->UpdateFailNumberReached();
        return $remainingTime > 0 || $failThresholdReached;
    }

    private function getUpdateFailNumber()
    {
        $this->AdminSetting = ClassRegistry::init('AdminSetting');
        $updateFailNumber = $this->AdminSetting->getSetting('update_fail_number');
        return ($updateFailNumber !== false && $updateFailNumber !== '') ? $updateFailNumber : 0;
    }

    public function resetUpdateFailNumber()
    {
        $this->AdminSetting = ClassRegistry::init('AdminSetting');
        $this->AdminSetting->changeSetting('update_fail_number', 0);
    }

    private function __increaseUpdateFailNumber()
    {
        $this->AdminSetting = ClassRegistry::init('AdminSetting');
        $updateFailNumber = $this->AdminSetting->getSetting('update_fail_number');
        $this->AdminSetting->changeSetting('update_fail_number', $updateFailNumber+1);
    }

    public function UpdateFailNumberReached()
    {
        return $this->getUpdateFailNumber() > 3;
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
        $cleanDB = $this->AdminSetting->getSetting('clean_db');
        if ($cleanDB === false || $cleanDB == 1) {
            $this->cleanCacheFiles();
            $this->AdminSetting->changeSetting('clean_db', 0);
        }
    }

    /**
     * @param string $db_version
     * @return array
     */
    protected function findUpgrades($db_version)
    {
        $updates = array();
        if (strpos($db_version, '.')) {
            $version = explode('.', $db_version);
            foreach (self::OLD_DB_CHANGES as $major => $rest) {
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
        foreach (self::DB_CHANGES as $db_change => $requiresLogout) {
            if ($db_version < $db_change) {
                $updates[$db_change] = $requiresLogout;
            }
        }
        return $updates;
    }

    private function __generateCorrelations()
    {
        if (Configure::read('MISP.background_jobs')) {
            /** @var Job $job */
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob(
                'SYSTEM',
                Job::WORKER_DEFAULT,
                'generate correlation',
                'All attributes',
                'Job created.'
            );

            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_ADMIN,
                [
                    'jobGenerateCorrelation',
                    $jobId
                ],
                true,
                $jobId
            );

        }
        return true;
    }

    private function removeDuplicatedUUIDs()
    {
        $removedResults = array(
            'Event' => $this->removeDuplicateEventUUIDs(),
            'Attribute' => $this->removeDuplicateAttributeUUIDs(),
            'Object' => $this->__removeDuplicateUUIDsGeneric(ClassRegistry::init('MispObject'), 'timestamp'),
            'Sighting' => $this->__removeDuplicateUUIDsGeneric(ClassRegistry::init('Sighting'), 'date_sighting'),
            'Dashboard' => $this->__removeDuplicateUUIDsGeneric(ClassRegistry::init('Dashboard'), 'timestamp'),
            'Inbox' => $this->__removeDuplicateUUIDsGeneric(ClassRegistry::init('Inbox'), 'timestamp'),
            'TagCollection' => $this->__removeDuplicateUUIDsGeneric(ClassRegistry::init('TagCollection')),
            // 'GalaxyCluster' => $this->__removeDuplicateUUIDsGeneric(ClassRegistry::init('GalaxyCluster')),
        );
        $this->Log->createLogEntry('SYSTEM', 'update_database', 'Server', 0, __('Removed duplicated UUIDs'), __('Event: %s, Attribute: %s, Object: %s, Sighting: %s, Dashboard: %s, Inbox: %s, TagCollection: %s', h($removedResults['Event']), h($removedResults['Attribute']), h($removedResults['Object']), h($removedResults['Sighting']), h($removedResults['Dashboard']), h($removedResults['Inbox']), h($removedResults['TagCollection'])));
    }

    private function __removeDuplicateUUIDsGeneric($model, $sort_by=false): int
    {
        $className = get_class($model);
        $alias = $model->alias;
        $this->Log = ClassRegistry::init('Log');
        $duplicates = $model->find('all', array(
            'fields' => array('uuid', 'count(uuid) as occurrence'),
            'recursive' => -1,
            'group' => array('uuid HAVING occurrence > 1'),
        ));
        $counter = 0;
        foreach ($duplicates as $duplicate) {
            $options = [
                'recursive' => -1,
                'conditions' => array('uuid' => $duplicate[$alias]['uuid']),
            ];
            if (!empty($sort_by)) {
                $options['order'] = "$sort_by DESC";
            }
            $fetched_duplicates = $model->find('all', $options);
            unset($fetched_duplicates[0]);
            foreach ($fetched_duplicates as $fetched_duplicate) {
                $model->delete($fetched_duplicate[$alias]['id']);
                $this->Log->createLogEntry('SYSTEM', 'delete', $className, $fetched_duplicate[$alias]['id'], __('Removed %s (%s)', $className, $fetched_duplicate[$alias]['id']), __('%s\'s UUID duplicated (%s)', $className, $fetched_duplicate[$alias]['uuid']));
                $counter++;
            }
        }
        return $counter;
    }

    private function removeDuplicateAttributeUUIDs()
    {
        $this->Attribute = ClassRegistry::init('Attribute');
        $this->Log = ClassRegistry::init('Log');
        $duplicates = $this->Attribute->find('all', array(
            'fields' => array('Attribute.uuid', 'count(Attribute.uuid) as occurrence'),
            'recursive' => -1,
            'group' => array('Attribute.uuid HAVING occurrence > 1'),
            'order' => false,
        ));
        $counter = 0;
        foreach ($duplicates as $duplicate) {
            $attributes = $this->Attribute->find('all', array(
                'recursive' => -1,
                'conditions' => array('uuid' => $duplicate['Attribute']['uuid']),
                'contain' => array(
                    'AttributeTag' => array(
                        'fields' => array('tag_id')
                    )
                ),
                'order' => 'timestamp DESC',
            ));
            $tagIDsOfFirstAttribute = Hash::extract($attributes[0]['AttributeTag'], '{n}.tag_id');
            $eventIDOfFirstAttribute = $attributes[0]['Attribute']['event_id'];
            unset($attributes[0]);
            foreach ($attributes as $attribute) {
                $tagIDs = Hash::extract($attribute['AttributeTag'], '{n}.tag_id');
                $logTag = false;
                $logEventID = false;
                if (empty(array_diff($tagIDs, $tagIDsOfFirstAttribute))) {
                    $logTag = true;
                }
                if ($eventIDOfFirstAttribute != $attribute['Attribute']['event_id']) {
                    $logEventID = true;
                }
                $success = $this->Attribute->delete($attribute['Attribute']['id']);
                if (empty($success)) {
                    $this->Log->createLogEntry('SYSTEM', 'delete', 'Attribute', $attribute['Attribute']['id'], __('Could not remove attribute (%s)', $attribute['Attribute']['id']), __('Deletion was rejected.'));
                    continue;
                }
                $logMessage = __('Attribute\'s UUID duplicated (%s).', $attribute['Attribute']['uuid']);
                if ($logEventID) {
                    $logMessage .= __(' Was part of another event_id (%s) than the one that was kept (%s).', $attribute['Attribute']['event_id'], $eventIDOfFirstAttribute);
                } else if ($logTag) {
                    $logMessage .= __(' Tag IDs attached [%s]', implode($tagIDs));
                } else {
                }
                $this->Log->createLogEntry('SYSTEM', 'delete', 'Attribute', $attribute['Attribute']['id'], __('Removed attribute (%s)', $attribute['Attribute']['id']), $logMessage);
                $counter++;
            }
        }
        return $counter;
    }

    private function removeDuplicateEventUUIDs()
    {
        $this->Event = ClassRegistry::init('Event');
        $this->Log = ClassRegistry::init('Log');
        $duplicates = $this->Event->find('all', array(
                'fields' => array('Event.uuid', 'count(Event.uuid) as occurrence'),
                'recursive' => -1,
                'group' => array('Event.uuid HAVING occurrence > 1'),
        ));
        $counter = 0;

        // load this so we can remove the blocklist item that will be created, this is the one case when we do not want it.
        if (Configure::read('MISP.enableEventBlocklisting') !== false) {
            $this->EventBlocklist = ClassRegistry::init('EventBlocklist');
        }

        foreach ($duplicates as $duplicate) {
            $events = $this->Event->find('all', array(
                'recursive' => -1,
                'conditions' => array('uuid' => $duplicate['Event']['uuid']),
                'order' => 'timestamp DESC',
            ));
            unset($events[0]);
            foreach ($events as $event) {
                $uuid = $event['Event']['uuid'];
                $this->Event->delete($event['Event']['id']);
                $this->Log->createLogEntry('SYSTEM', 'delete', 'Event', $event['Event']['id'], __('Removed event (%s)', $event['Event']['id']), __('Event\'s UUID duplicated (%s)', $event['Event']['uuid']));
                $counter++;
                // remove the blocklist entry that we just created with the event deletion, if the feature is enabled
                // We do not want to block the UUID, since we just deleted a copy
                if (Configure::read('MISP.enableEventBlocklisting') !== false) {
                    $this->EventBlocklist->deleteAll(array('EventBlocklist.event_uuid' => $uuid));
                }
            }
        }
        return $counter;
    }

    public function checkFilename($filename)
    {
        return preg_match('@^([a-z0-9_.]+[a-z0-9_.\- ]*[a-z0-9_.\-]|[a-z0-9_.])+$@i', $filename);
    }

    /**
     * Similar method as `setupRedis`, but this method throw exception if Redis cannot be reached.
     * @return Redis
     * @throws Exception
     * @deprecated
     */
    public function setupRedisWithException()
    {
        return RedisTool::init();
    }

    /**
     * Method for backward compatibility.
     * @deprecated
     * @see AppModel::setupRedisWithException
     * @return bool|Redis
     */
    public function setupRedis()
    {
        try {
            return RedisTool::init();
        } catch (Exception $e) {
            return false;
        }
    }

    public function getKafkaPubTool()
    {
        if (!$this->loadedKafkaPubTool) {
            App::uses('KafkaPubTool', 'Tools');
            $kafkaPubTool = new KafkaPubTool();
            $rdkafkaIni = Configure::read('Plugin.Kafka_rdkafka_config');
            $rdkafkaIni = mb_ereg_replace("/\:\/\//", '', $rdkafkaIni);
            $kafkaConf = array();
            if (!empty($rdkafkaIni)) {
                $kafkaConf = parse_ini_file($rdkafkaIni);
            }
            $brokers = Configure::read('Plugin.Kafka_brokers');
            $kafkaPubTool->initTool($brokers, $kafkaConf);
            $this->loadedKafkaPubTool = $kafkaPubTool;
        }
        return $this->loadedKafkaPubTool;
    }

    public function publishKafkaNotification($topicName, $data, $action = false)
    {
        $kafkaTopic = $this->kafkaTopic($topicName);
        if ($kafkaTopic) {
            $this->getKafkaPubTool()->publishJson($kafkaTopic, $data, $action);
        }
    }

    /**
     * @return PubSubTool
     */
    public function getPubSubTool()
    {
        if (!self::$loadedPubSubTool) {
            App::uses('PubSubTool', 'Tools');
            $pubSubTool = new PubSubTool();
            $pubSubTool->initTool();
            self::$loadedPubSubTool = $pubSubTool;
        }
        return self::$loadedPubSubTool;
    }

    /**
     * @return BackgroundJobsTool
     */
    public function getBackgroundJobsTool(): BackgroundJobsTool
    {
        if (!self::$loadedBackgroundJobsTool) {
            App::uses('BackgroundJobsTool', 'Tools');

            // TODO: remove after CakeResque is deprecated
            $settings = ['enabled' => false];
            if (Configure::read('SimpleBackgroundJobs.enabled')) {
                $settings = Configure::read('SimpleBackgroundJobs');
            }

            $backgroundJobsTool = new BackgroundJobsTool($settings);
            self::$loadedBackgroundJobsTool = $backgroundJobsTool;
        }
        return self::$loadedBackgroundJobsTool;
    }

    /**
     * Generate a generic subquery - options needs to include conditions
     *
     * @param AppModel $model
     * @param array $options
     * @param string $lookupKey
     * @param bool $negation
     * @return string[]
     */
    protected function subQueryGenerator(AppModel $model, array $options, $lookupKey, $negation = false)
    {
        $defaults = array(
            'fields' => array('*'),
            'table' => $model->table,
            'alias' => $model->alias,
            'limit' => null,
            'offset' => null,
            'joins' => array(),
            'conditions' => array(),
            'group' => false,
            'recursive' => -1
        );
        $params = array();
        foreach ($defaults as $key => $defaultValue) {
            if (isset($options[$key])) {
                $params[$key] = $options[$key];
            } else {
                $params[$key] = $defaultValue;
            }
        }
        $db = $model->getDataSource();
        $subQuery = $db->buildStatement($params, $model);
        if ($negation) {
            $subQuery = $lookupKey . ' NOT IN (' . $subQuery . ') ';
        } else {
            $subQuery = $lookupKey . ' IN (' . $subQuery . ') ';
        }
        return [$subQuery];
    }

    /**
     * Returns estimated number of table rows
     * @return int
     */
    public function tableRows()
    {
        $rows = $this->query("SELECT TABLE_ROWS FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = '{$this->table}';");
        return $rows[0]['TABLES']['TABLE_ROWS'];
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

    public function setupHttpSocket($server, $HttpSocket = null, $timeout = false)
    {
        if (empty($HttpSocket)) {
            App::uses('SyncTool', 'Tools');
            $syncTool = new SyncTool();
            $HttpSocket = $syncTool->setupHttpSocket($server, $timeout);
        }
        return $HttpSocket;
    }

    /**
     * @param array $server
     * @param string $model
     * @return array[]
     * @throws JsonException
     */
    public function setupSyncRequest(array $server, $model = 'Server')
    {
        $version = implode('.', $this->checkMISPVersion());
        $commit = $this->checkMIPSCommit();

        $authkey = $server[$model]['authkey'];
        App::uses('EncryptedValue', 'Tools');
        if (EncryptedValue::isEncrypted($authkey)) {
            $authkey = (string)new EncryptedValue($authkey);
        }

        return array(
            'header' => array(
                'Authorization' => $authkey,
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'User-Agent' => 'MISP ' . $version . (empty($commit) ? '' : ' - #' . $commit),
            )
        );
    }

    /**
     * Returns MISP version from VERSION.json file as array with major, minor and hotfix keys.
     *
     * @return array
     * @throws Exception
     */
    public function checkMISPVersion()
    {
        static $versionArray;
        if ($versionArray === null) {
            $versionArray = FileAccessTool::readJsonFromFile(ROOT . DS . 'VERSION.json', true);
        }
        return $versionArray;
    }

    /**
     * Returns MISP commit hash.
     *
     * @return false|string
     */
    public function checkMIPSCommit()
    {
        static $commit;
        if ($commit === null) {
            App::uses('GitTool', 'Tools');
            try {
                $commit = GitTool::currentCommit(ROOT);
            } catch (Exception $e) {
                $this->logException('Could not get current git commit', $e, LOG_NOTICE);
                $commit = false;
            }
        }
        return $commit;
    }

    // take filters in the {"OR" => [foo], "NOT" => [bar]} format along with conditions and set the conditions
    public function generic_add_filter($conditions, &$filter, $keys)
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
                if ($f === -1) {
                    foreach ($keys as $key) {
                        if ($this->checkParam($key)) {
                            $temp['OR'][$key][] = -1;
                        }
                    }
                    continue;
                }
                // split the filter params into two lists, one for substring searches one for exact ones
                if (is_string($f) && ($f[strlen($f) - 1] === '%' || $f[0] === '%')) {
                    foreach ($keys as $key) {
                        if ($this->checkParam($key)) {
                            if ($operator === 'NOT') {
                                $temp[] = array($key . ' NOT LIKE' => $f);
                            } else {
                                $temp[] = array($key . ' LIKE' => $f);
                                $temp[] = array($key => $f);
                            }
                        }
                    }
                } else {
                    foreach ($keys as $key) {
                        if ($this->checkParam($key)) {
                            if ($operator === 'NOT') {
                                $temp[$key . ' !='][] = $f;
                            } else {
                                $temp['OR'][$key][] = $f;
                            }
                        }
                    }
                }
            }
            $conditions['AND'][] = array($operator_composition[$operator] => $temp);
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
                $f = strval($f);
                if ($f !== '') {
                    if ($f[0] === '!') {
                        $filter['NOT'][] = substr($f, 1);
                    } else {
                        $filter['OR'][] = $f;
                    }
                }
            }
            return $filter;
        }
        if (!isset($filter['OR']) && !isset($filter['NOT']) && !isset($filter['AND'])) {
            $temp = array();
            foreach ($filter as $param) {
                $param = strval($param);
                if (!empty($param)) {
                    if ($param[0] === '!') {
                        $temp['NOT'][] = substr($param, 1);
                    } else {
                        $temp['OR'][] = $param;
                    }
                }
            }
            $filter = $temp;
        }
        return $filter;
    }

    protected function convert_to_memory_limit_to_mb($val)
    {
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
        switch ($unit) {
            case 'g':
                $val *= 1024;
                // no break
            case 'm':
                $val *= 1024;
                // no break
            case 'k':
                $val *= 1024;
        }
        return $val / (1024 * 1024);
    }

    private function __bumpReferences()
    {
        $this->Event = ClassRegistry::init('Event');
        $this->AdminSetting = ClassRegistry::init('AdminSetting');
        $existingSetting = $this->AdminSetting->find('first', array(
            'conditions' => array('AdminSetting.setting' => 'update_23')
        ));
        if (empty($existingSetting)) {
            $this->AdminSetting->create();
            $data = array(
                'setting' => 'update_23',
                'value' => 1
            );
            $this->AdminSetting->save($data);
            $references = $this->Event->Object->ObjectReference->find('list', array(
                'recursive' => -1,
                'fields' => array('ObjectReference.event_id', 'ObjectReference.event_id'),
                'group' => array('ObjectReference.event_id')
            ));
            $event_ids = array();
            $object_ids = array();
            foreach ($references as $reference) {
                $event = $this->Event->find('first', array(
                    'conditions' => array(
                        'Event.id' => $reference,
                        'Event.locked' => 0
                    ),
                    'recursive' => -1,
                    'fields' => array('Event.id', 'Event.locked')
                ));
                if (!empty($event)) {
                    $event_ids[] = $event['Event']['id'];
                    $event_references = $this->Event->Object->ObjectReference->find('list', array(
                        'conditions' => array('ObjectReference.event_id' => $reference),
                        'recursive' => -1,
                        'fields' => array('ObjectReference.object_id', 'ObjectReference.object_id')
                    ));
                    $object_ids = array_merge($object_ids, array_values($event_references));
                }
            }
            if (!empty($object_ids)) {
                $this->Event->Object->updateAll(
                    array(
                    'Object.timestamp' => 'Object.timestamp + 1'
                    ),
                    array('Object.id' => $object_ids)
                );
                $this->Event->updateAll(
                    array(
                    'Event.timestamp' => 'Event.timestamp + 1'
                    ),
                    array('Event.id' => $event_ids)
                );
            }
            $this->Log = ClassRegistry::init('Log');
            $this->Log->create();
            $entry = array(
                'org' => 'SYSTEM',
                'model' => 'Server',
                'model_id' => 0,
                'email' => 'SYSTEM',
                'action' => 'update_database',
                'user_id' => 0,
                'title' => 'Bumped the timestamps of locked events containing object references.',
                'change' => sprintf('Event timestamps updated: %s; Object timestamps updated: %s', count($event_ids), count($object_ids))
            );
            $this->Log->saveOrFailSilently($entry);
        }
        return true;
    }

    public function generateRandomFileName()
    {
        return (new RandomTool())->random_str(false, 12);
    }

    /**
     * @param string|int $delta
     * @return int Timestamp
     */
    public function resolveTimeDelta($delta)
    {
        if (is_numeric($delta)) {
            return (int)$delta;
        }

        $multiplierArray = ['d' => 86400, 'h' => 3600, 'm' => 60, 's' => 1];
        $lastChar = strtolower(substr($delta, -1));
        if (!is_numeric($lastChar) && isset($multiplierArray[$lastChar])) {
            $multiplier = $multiplierArray[$lastChar];
            $timeDelta = substr($delta, 0, -1);
            if (!is_numeric($timeDelta)) {
                $this->log('Invalid time filter format ' . $delta, LOG_NOTICE);
                return time() + 1;
            }
            return time() - ($timeDelta * $multiplier);
        }

        $time = strtotime($delta);
        if ($time !== false) {
            return $time;
        }

        $this->log('Invalid time filter format ' . $delta, LOG_NOTICE);
        return time() + 1;
    }

    private function __fixServerPullPushRules()
    {
        $this->Server = ClassRegistry::init('Server');
        $servers = $this->Server->find('all', array('recursive' => -1));
        foreach ($servers as $server) {
            $changed = false;
            if (empty($server['Server']['pull_rules'])) {
                $server['Server']['pull_rules'] = '[]';
                $changed = true;
            }
            if (empty($server['Server']['push_rules'])) {
                $server['Server']['push_rules'] = '[]';
                $changed = true;
            }
            if ($changed) {
                $this->Server->save($server);
            }
        }
    }

    /**
     * Optimised version of CakePHP _findList method when just one or two fields are set from same model
     * @param string $state
     * @param array $query
     * @param array $results
     * @return array
     */
    protected function _findList($state, $query, $results = [])
    {
        if ($state === 'before') {
            return parent::_findList($state, $query, $results);
        }

        if (empty($results)) {
            return [];
        }

        if ($query['list']['groupPath'] === null) {
            $keyPath = explode('.', $query['list']['keyPath']);
            $valuePath = explode('.', $query['list']['valuePath']);
            if ($keyPath[1] === $valuePath[1]) { // same model
                return array_column(array_column($results, $keyPath[1]), $valuePath[2], $keyPath[2]);
            }
        }

        return parent::_findList($state, $query, $results);
    }

    /**
     * Find method that allows to fetch just one column from database.
     * @param $state
     * @param $query
     * @param array $results
     * @return array
     * @throws InvalidArgumentException
     */
    protected function _findColumn($state, $query, $results = array())
    {
        if ($state === 'before') {
            if (isset($query['fields']) && is_array($query['fields']) && count($query['fields']) === 1) {
                if (strpos($query['fields'][0], '.') === false) {
                    $query['fields'][0] = $this->alias . '.' . $query['fields'][0];
                }

                $query['column'] = $query['fields'][0];
                if (isset($query['unique']) && $query['unique']) {
                    $query['fields'] = array("DISTINCT {$query['fields'][0]}");
                } else {
                    $query['fields'] = array($query['fields'][0]);
                }
            } else if (!isset($query['fields'])) {
                throw new InvalidArgumentException("This method requires `fields` option defined.");
            } else {
                throw new InvalidArgumentException("Invalid number of column, expected one, " . count($query['fields']) . " given");
            }

            if (!isset($query['recursive'])) {
                $query['recursive'] = -1;
            }

            return $query;
        }

        // Faster version of `Hash::extract`
        foreach (explode('.', $query['column']) as $part) {
            $results = array_column($results, $part);
        }
        return $results;
    }

    /**
     * @param string $field
     * @param AppModel $model
     * @param array $conditions
     */
    public function addCountField($field, AppModel $model, array $conditions)
    {
        $db = $this->getDataSource();
        $subQuery = $db->buildStatement(
            array(
                'fields'     => ['COUNT(*)'],
                'table'      => $db->fullTableName($model),
                'alias'      => $model->alias,
                'conditions' => $conditions,
            ),
            $model
        );
        $this->virtualFields[$field] = $subQuery;
    }

    /**
     * Log exception with backtrace and with nested exceptions.
     *
     * @param string $message
     * @param Exception $exception
     * @param int $type
     * @return bool
     */
    protected function logException($message, Exception $exception, $type = LOG_ERR)
    {
        // If Sentry is installed, send exception to Sentry
        if (function_exists('\Sentry\captureException') && $type <= LOG_ERR) {
            \Sentry\captureException(new Exception($message, $type, $exception));
        }

        do {
            $message .= sprintf("\n[%s] %s", get_class($exception), $exception->getMessage());
            $message .= "\nStack Trace:\n" . $exception->getTraceAsString();
            $exception = $exception->getPrevious();
        } while ($exception !== null);

        return $this->log($message, $type);
    }

    /**
     * Decodes JSON string and throws exception if string is not valid JSON or if is not array.
     *
     * @param string $json
     * @return array
     * @throws JsonException
     * @throws UnexpectedValueException
     * @deprecated
     */
    protected function jsonDecode($json)
    {
        return JsonTool::decodeArray($json);
    }

    /**
     * Faster version of default `hasAny` method
     * @param array|null $conditions
     * @return bool
     */
    public function hasAny($conditions = null)
    {
        return (bool)$this->find('first', [
            'fields' => [$this->alias . '.' . $this->primaryKey],
            'conditions' => $conditions,
            'recursive' => -1,
            'callbacks' => false,
            'order' => [], // disable order
        ]);
    }

    /**
     * Faster version of original `isUnique` method
     * {@inheritDoc}
     */
    public function isUnique($fields, $or = true)
    {
        if (is_array($or)) {
            $isRule = (
                array_key_exists('rule', $or) &&
                array_key_exists('required', $or) &&
                array_key_exists('message', $or)
            );
            if (!$isRule) {
                $args = func_get_args();
                $fields = $args[1];
                $or = $args[2] ?? true;
            }
        }
        if (!is_array($fields)) {
            $fields = func_get_args();
            $fieldCount = count($fields) - 1;
            if (is_bool($fields[$fieldCount])) {
                $or = $fields[$fieldCount];
                unset($fields[$fieldCount]);
            }
        }

        foreach ($fields as $field => $value) {
            if (is_numeric($field)) {
                unset($fields[$field]);

                $field = $value;
                $value = null;
                if (isset($this->data[$this->alias][$field])) {
                    $value = $this->data[$this->alias][$field];
                }
            }

            if (strpos($field, '.') === false) {
                unset($fields[$field]);
                $fields[$this->alias . '.' . $field] = $value;
            }
        }

        if ($or) {
            $fields = array('or' => $fields);
        }

        if (!empty($this->id)) {
            $fields[$this->alias . '.' . $this->primaryKey . ' !='] = $this->id;
        }

        return !$this->hasAny($fields);
    }

    /**
     * Faster version of original `exists` method
     * {@inheritDoc}
     */
    public function exists($id = null)
    {
        if ($id === null) {
            $id = $this->getID();
        }

        if ($id === false || $this->useTable === false) {
            return false;
        }

        return $this->hasAny([$this->alias . '.' . $this->primaryKey => $id]);
    }

    /**
     * @param int $value Timestamp in microseconds
     * @return string
     */
    protected function microTimestampToIso($value)
    {
        $sec = (int)($value / 1000000);
        $micro = $value % 1000000;
        $micro = str_pad($micro, 6, "0", STR_PAD_LEFT);
        return DateTime::createFromFormat('U.u', "$sec.$micro")->format('Y-m-d\TH:i:s.uP');
    }

    /**
     * @return AttachmentTool
     */
    protected function loadAttachmentTool()
    {
        if ($this->attachmentTool === null) {
            $this->attachmentTool = new AttachmentTool();
        }

        return $this->attachmentTool;
    }

    /**
     * @return AttachmentScan
     */
    protected function loadAttachmentScan()
    {
        if ($this->AttachmentScan === null) {
            $this->AttachmentScan = ClassRegistry::init('AttachmentScan');
        }

        return $this->AttachmentScan;
    }

    /**
     * @return Log
     */
    protected function loadLog()
    {
        if (!isset($this->Log)) {
            $this->Log = ClassRegistry::init('Log');
        }
        return $this->Log;
    }

    /**
     * @param string $name
     * @return string|null Null when Kafka is not enabled, topic is not enabled or topic is not defined
     */
    protected function kafkaTopic($name)
    {
        static $kafkaEnabled;
        if ($kafkaEnabled === null) {
            $kafkaEnabled = (bool)Configure::read('Plugin.Kafka_enable');
        }
        if ($kafkaEnabled) {
            if (!Configure::read("Plugin.Kafka_{$name}_notifications_enable")) {
                return null;
            }
            return Configure::read("Plugin.Kafka_{$name}_notifications_topic") ?: null;
        }
        return null;
    }

    /**
     * @param string $name
     * @return bool
     */
    protected function pubToZmq($name)
    {
        static $zmqEnabled;
        if ($zmqEnabled === null) {
            $zmqEnabled = (bool)Configure::read('Plugin.ZeroMQ_enable');
        }
        if ($zmqEnabled) {
            return Configure::read("Plugin.ZeroMQ_{$name}_notifications_enable");
        }
        return false;
    }

    /**
     * @return bool Returns true if database is MySQL/Mariadb, false for PostgreSQL
     */
    protected function isMysql()
    {
        $dataSource = ConnectionManager::getDataSource('default');
        return $dataSource instanceof Mysql;
    }

    /**
     * executeTrigger
     *
     * @param string $trigger_id
     * @param array $data Data to be passed to the workflow
     * @param array $blockingErrors Errors will be appened if any
     * @param array $logging If the execution failure should be logged
     * @return boolean If the execution for the blocking path was a success
     */
    protected function executeTrigger($trigger_id, array $data=[], array &$blockingErrors=[], array $logging=[]): bool
    {
        if ($this->isTriggerCallable($trigger_id)) {
           $success = $this->Workflow->executeWorkflowForTriggerRouter($trigger_id, $data, $blockingErrors, $logging);
           if (!empty($logging) && empty($success)) {
                $logging['message'] = !empty($logging['message']) ? $logging['message'] : __('Error while executing workflow.');
                $errorMessage = implode(', ', $blockingErrors);
                $this->loadLog()->createLogEntry('SYSTEM', $logging['action'], $logging['model'], $logging['id'], $logging['message'], __('Returned message: %s', $errorMessage));
           }
           return $success;
        }
        return true;
    }

    protected function isTriggerCallable($trigger_id): bool
    {
        static $workflowEnabled;
        if ($workflowEnabled === null) {
            $workflowEnabled = (bool)Configure::read('Plugin.Workflow_enable');
        }

        if (!$workflowEnabled) {
            return false;
        }

        if ($this->Workflow === null) {
            $this->Workflow = ClassRegistry::init('Workflow');
        }
        return $this->Workflow->checkTriggerEnabled($trigger_id) &&
            $this->Workflow->checkTriggerListenedTo($trigger_id);
    }

    /**
     * Use different CakeEventManager to fix memory leak
     * @return CakeEventManager
     */
    public function getEventManager()
    {
        if (empty($this->_eventManager)) {
            $this->_eventManager = new BetterCakeEventManager();
            $this->_eventManager->attach($this->Behaviors);
            $this->_eventManager->attach($this);
        }
        return $this->_eventManager;
    }

    private function __retireOldCorrelationEngine($user = null)
    {
        if ($user === null) {
            $user = [
                'id' => 0,
                'email' => 'SYSTEM',
                'Organisation' => [
                    'name' => 'SYSTEM'
                ]
            ];
        }
        $this->Correlation = ClassRegistry::init('Correlation');
        $this->Attribute = ClassRegistry::init('Attribute');
        if (!Configure::read('MISP.background_jobs')) {
            $this->Correlation->truncate($user, 'Legacy');
            $this->Attribute->generateCorrelation();
        } else {
            $job = ClassRegistry::init('Job');
            $jobId = $job->createJob(
                'SYSTEM',
                Job::WORKER_DEFAULT,
                'truncate table',
                $this->Correlation->validEngines['Legacy'],
                'Job created.'
            );
            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_ADMIN,
                [
                    'truncateTable',
                    0,
                    'Legacy',
                    $jobId
                ],
                true,
                $jobId
            );
            $jobId = $job->createJob(
                'SYSTEM',
                Job::WORKER_DEFAULT,
                'generate correlation',
                'All attributes',
                'Job created.'
            );

            $this->getBackgroundJobsTool()->enqueue(
                BackgroundJobsTool::DEFAULT_QUEUE,
                BackgroundJobsTool::CMD_ADMIN,
                [
                    'jobGenerateCorrelation',
                    $jobId
                ],
                true,
                $jobId
            );
        }
    }

    public function removeDuplicateCorrelationEntries($table_name = 'default_correlations')
    {
        // If there are duplicate entries, the query creating the `unique_correlation` index will result in an integrity constraint violation.
        // The query below cleans up potential duplicates before creating the constraint.
        return $this->query("
            DELETE FROM `$table_name` WHERE id in (
                SELECT m_id FROM (
                    SELECT MAX(corr_a.id) as m_id, CONCAT(corr_a.attribute_id, \" - \", corr_a.1_attribute_id, \" - \", corr_a.value_id) as uniq FROM `$table_name` corr_a
                    INNER JOIN `$table_name` corr_b on corr_a.attribute_id = corr_b.attribute_id
                    WHERE
                        corr_a.attribute_id = corr_b.attribute_id AND
                        corr_a.1_attribute_id = corr_b.1_attribute_id AND
                        corr_a.value_id = corr_b.value_id AND
                        corr_a.id <> corr_b.id
                    GROUP BY uniq
                ) as c
            );
        ");
    }

    public function findOrder($order, $orderModel, $validOrderFields)
    {
        if (!is_array($order)) {
            $orderRules = explode(' ', strtolower($order));
            $orderField = explode('.', $orderRules[0]);
            $orderField = end($orderField);
            if (in_array($orderField, $validOrderFields, true)) {
                $direction = 'asc';
                if (!empty($orderRules[1]) && trim($orderRules[1]) === 'desc') {
                    $direction = 'desc';
                }
            } else {
                return null;
            }
            return $orderModel . '.' . $orderField . ' ' . $direction;
        }
        return null;
    }

    /**
     * @return string|null
     */
    public function _remoteIp()
    {
        static $remoteIp;

        if ($remoteIp) {
            return $remoteIp;
        }

        $clientIpHeader = Configure::read('MISP.log_client_ip_header');
        if ($clientIpHeader && isset($_SERVER[$clientIpHeader])) {
            $headerValue = $_SERVER[$clientIpHeader];
            // X-Forwarded-For can contain multiple IPs, see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For
            if (($commaPos = strpos($headerValue, ',')) !== false) {
                $headerValue = substr($headerValue, 0, $commaPos);
            }
            $remoteIp = trim($headerValue);
        } else {
            $remoteIp = $_SERVER['REMOTE_ADDR'] ?? null;
        }

        return $remoteIp;
    }

    public function find($type = 'first', $query = array())
    {
        if (!empty($query['order']) && $this->validOrderClause($query['order']) === false) {
            throw new InvalidArgumentException('Invalid order clause');
        }
        $results = parent::find($type, $query);
        if (!empty($query['includeAnalystData']) && $this->Behaviors->enabled('AnalystDataParent')) {
            if ($type === 'first') {
                $results[$this->alias] = array_merge($results[$this->alias], $this->attachAnalystData($results[$this->alias]));
            } else if ($type === 'all') {
                foreach ($results as $k => $result) {
                    $results[$k][$this->alias] = array_merge($results[$k][$this->alias], $this->attachAnalystData($results[$k][$this->alias]));
                }
            }
        }
        return $results;
    }

    private function validOrderClause($order)
    {
        $pattern = '/^[\w\_\-\.\(\) ]+$/';
        if (is_string($order) && preg_match($pattern, $order)) {
            return true;
        }

        if (is_array($order)) {
            foreach ($order as $key => $value) {
                if (is_string($key) && is_string($value) && preg_match($pattern, $key) && in_array(strtolower($value), ['asc', 'desc'])) {
                    return true;
                }
                if (is_numeric($key) && is_string($value) && preg_match($pattern, $value)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function checkParam($param)
    {
        return preg_match('/^[\w\_\-\. ]+$/', $param);
    }

    public function moveImages()
    {
        $oldImageDir = APP . 'webroot/img';
        $newImageDir = APP . 'files/img';
        $oldOrgDir = new Folder($oldImageDir . '/orgs');
        $oldCustomDir = new Folder($oldImageDir . '/custom');
        $result = $oldOrgDir->copy([
            'from' => $oldImageDir . '/orgs',
            'to' => $newImageDir . '/orgs',
            'scheme' => Folder::OVERWRITE,
            'recursive' => true
        ]);
        if ($result) {
            $oldOrgDir->delete();
        }
        $result = $oldCustomDir->copy([
            'from' => $oldImageDir . '/custom',
            'to' => $newImageDir . '/custom',
            'scheme' => Folder::OVERWRITE,
            'recursive' => true
        ]);
        if ($result) {
            $oldCustomDir->delete();
        }
        return true;
    }
}
