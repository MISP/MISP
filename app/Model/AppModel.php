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

/**
 * Application model for Cake.
 *
 * Add your application-wide methods in the class below, your models
 * will inherit them.
 *
 * @package       app.Model
 */
class AppModel extends Model {

/**
 * Model Name
 *
 * @var string
 */
	public $name;

	public function __construct($id = false, $table = null, $ds = null) {
		parent::__construct($id, $table, $ds);

		$this->name = get_class($this);
	}

	// major -> minor -> hotfix -> requires_logout
	public $db_changes = array(
		2 => array(
			4 => array(18 => false, 19 => false, 20 => false, 25 => false, 27 => false, 32 => false, 33 => true, 38 => true, 39 => true, 40 => false, 42 => false, 44 => false, 45 => false)
		)
	);

	// Generic update script
	// add special cases where the upgrade does more than just update the DB
	// this could become useful in the future
	public function updateMISP($command) {
		switch ($command) {
			case '2.4.20':
				$this->updateDatabase($command);
				$this->ShadowAttribute = ClassRegistry::init('ShadowAttribute');
				$this->ShadowAttribute->upgradeToProposalCorrelation();
				break;
			case '2.4.25':
				$this->updateDatabase($command);
				$newFeeds = array(
					array('provider' => 'CIRCL', 'name' => 'CIRCL OSINT Feed', 'url' => 'https://www.circl.lu/doc/misp/feed-osint', 'enabled' => false),
				);
				$this->__addNewFeeds($newFeeds);
				break;
			case '2.4.27':
				$newFeeds = array(
					array('provider' => 'Botvrij.eu', 'name' => 'The Botvrij.eu Data','url' => 'http://www.botvrij.eu/data/feed-osint', 'enabled' => false)
				);
				$this->__addNewFeeds($newFeeds);
				break;
			default:
				$this->updateDatabase($command);
				break;
		}
	}

	private function __addNewFeeds($feeds) {
		$this->Feed = ClassRegistry::init('Feed');
		$this->Log = ClassRegistry::init('Log');
		$feedNames = array();
		foreach ($feeds as &$feed) $feedNames[] = $feed['name'];
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
	public function updateDatabase($command) {
		$sql = '';
		$this->Log = ClassRegistry::init('Log');
		$clean = true;
		switch ($command) {
			case 'extendServerOrganizationLength':
				$sql = 'ALTER TABLE `servers` MODIFY COLUMN `organization` varchar(255) NOT NULL;';
				break;
			case 'convertLogFieldsToText':
				$sql = 'ALTER TABLE `logs` MODIFY COLUMN `title` text, MODIFY COLUMN `change` text;';
				break;
			case 'addEventBlacklists':
				$sql = 'CREATE TABLE IF NOT EXISTS `event_blacklists` ( `id` int(11) NOT NULL AUTO_INCREMENT, `event_uuid` varchar(40) COLLATE utf8_bin NOT NULL, `created` datetime NOT NULL, PRIMARY KEY (`id`), `event_info` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL, `comment` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL, `event_orgc` VARCHAR( 255 ) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin ;';
				break;
			case 'addOrgBlacklists':
				$sql = 'CREATE TABLE IF NOT EXISTS `org_blacklists` ( `id` int(11) NOT NULL AUTO_INCREMENT, `org_uuid` varchar(40) COLLATE utf8_bin NOT NULL, `created` datetime NOT NULL, PRIMARY KEY (`id`), `org_name` varchar(255) COLLATE utf8_bin NOT NULL, `comment` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin ;';
				break;
			case 'addEventBlacklistsContext':
				$sql = 'ALTER TABLE  `event_blacklists` ADD  `event_orgc` VARCHAR( 255 ) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL , ADD  `event_info` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL, ADD `comment` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL ;';
				break;
			case 'addSightings':
				$sql = "CREATE TABLE IF NOT EXISTS `sightings` (
				`id` int(11) NOT NULL AUTO_INCREMENT,
				`attribute_id` int(11) NOT NULL,
				`event_id` int(11) NOT NULL,
				`org_id` int(11) NOT NULL,
				`date_sighting` bigint(20) NOT NULL,
				PRIMARY KEY (`id`),
				INDEX `attribute_id` (`attribute_id`),
				INDEX `event_id` (`event_id`),
				INDEX `org_id` (`org_id`)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin ;";
				break;
			case 'makeAttributeUUIDsUnique':
				$this->__dropIndex('attributes', 'uuid');
				$sql = 'ALTER TABLE `attributes` ADD UNIQUE (uuid);';
				break;
			case 'makeEventUUIDsUnique':
				$this->__dropIndex('events', 'uuid');
				$sql = 'ALTER TABLE `events` ADD UNIQUE (uuid);';
				break;
			case 'cleanSessionTable':
				$sql = 'DELETE FROM `cake_sessions` WHERE `expires` < ' . time() . ';';
				$clean = false;
				break;
			case 'destroyAllSessions':
				$sql = 'DELETE FROM `cake_sessions`;';
				$clean = false;
				break;
			case 'addIPLogging':
				$sql = 'ALTER TABLE `logs` ADD  `ip` varchar(45) COLLATE utf8_bin DEFAULT NULL;';
				break;
			case 'addCustomAuth':
				$sqlArray[] = "ALTER TABLE `users` ADD `external_auth_required` tinyint(1) NOT NULL DEFAULT '0';";
				$sqlArray[] = 'ALTER TABLE `users` ADD `external_auth_key` text COLLATE utf8_bin;';
				break;
			case '24betaupdates':
				$sqlArray = array();
				$sqlArray[] = "ALTER TABLE `shadow_attributes` ADD  `proposal_to_delete` tinyint(1) NOT NULL DEFAULT '0';";

				$sqlArray[] = 'ALTER TABLE `logs` MODIFY  `change` text COLLATE utf8_bin NOT NULL;';

				$sqlArray[] = "CREATE TABLE IF NOT EXISTS `taxonomies` (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`namespace` varchar(255) COLLATE utf8_bin NOT NULL,
					`description` text COLLATE utf8_bin NOT NULL,
					`version` int(11) NOT NULL,
					`enabled` tinyint(1) NOT NULL DEFAULT '0',
					PRIMARY KEY (`id`)
					) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin ;";

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

				$sqlArray[] = 'ALTER TABLE  `sharing_groups` ADD  `sync_user_id` INT( 11 ) NOT NULL DEFAULT \'0\' AFTER  `org_id`;';

				$sqlArray[] = 'ALTER TABLE `users` ADD  `disabled` BOOLEAN NOT NULL;';
				$sqlArray[] = 'ALTER TABLE `users` ADD  `expiration` datetime DEFAULT NULL;';

				$sqlArray[] = 'UPDATE `roles` SET `perm_template` = 1 WHERE `perm_site_admin` = 1 OR `perm_admin` = 1';
				$sqlArray[] = 'UPDATE `roles` SET `perm_sharing_group` = 1 WHERE `perm_site_admin` = 1 OR `perm_sync` = 1';

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
				if ($version[0] > 5 || ($version[0] == 5 && $version[1] > 5)) $downgrade = false;

				// keep the fulltext for now, we can change it later to actually use it once we require MySQL 5.6 / or if we decide to move some tables to MyISAM

				foreach ($fieldsToIndex as $table => $fields) {
					$downgradeThis = false;
					$table_data = $this->query("SHOW TABLE STATUS WHERE Name = '" . $table . "'");
					if ($downgrade && $table_data[0]['TABLES']['Engine'] !== 'MyISAM') $downgradeThis = true;
					foreach ($fields as $field) {
						$extra = '';
						$this->__dropIndex($table, $field[0]);
						if (isset($field[2])) $extra = ' (' . $field[2] . ')';
						$sqlArray[] = 'ALTER TABLE `' . $table . '` ADD ' . ($downgradeThis ? 'INDEX' : $field[1]) . ' `' . $field[0] . '` (`' . $field[0] . '`' . $extra . ')';
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
				$sqlArray[] = "INSERT INTO `admin_settings` (`setting`, `value`) VALUES ('db_version', '2.4.0')";
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
				$sqlArray[] = "ALTER TABLE `roles` ADD `perm_tag_editor` tinyint(1) NOT NULL DEFAULT '0';";
				$sqlArray[] = 'UPDATE `roles` SET `perm_tag_editor` = 1 WHERE `perm_tagger` = 1';
				break;
			case '2.4.33':
				$sqlArray[] = "ALTER TABLE `users` ADD `force_logout` tinyint(1) NOT NULL DEFAULT '0';";
				break;
			case '2.4.38':
				$sqlArray[] = "CREATE TABLE IF NOT EXISTS `warninglists` (
					`id` int(11) NOT NULL AUTO_INCREMENT,
					`name` varchar(255) COLLATE utf8_bin NOT NULL,
					`type` varchar(255) COLLATE utf8_bin NOT NULL DEFAULT 'string',
					`description` text COLLATE utf8_bin NOT NULL,
					`version` int(11) NOT NULL DEFAULT '1',
					`enabled` tinyint(1) NOT NULL DEFAULT '0',
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
				$sqlArray[] = "ALTER TABLE `users` ADD `certif_public` longtext COLLATE utf8_bin NOT NULL DEFAULT '' AFTER `gpgkey`;";
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
				$sqlArray[] = "ALTER TABLE `attributes` ADD `deleted` tinyint(1) NOT NULL DEFAULT '0';";
				break;
			case '2.4.44':
				$sqlArray[] = "UPDATE `servers` SET `url` = TRIM(TRAILING '/' FROM `url`)";
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
			case 'fixNonEmptySharingGroupID':
				$sqlArray[] = 'UPDATE `events` SET `sharing_group_id` = 0 WHERE `distribution` != 4';
				$sqlArray[] = 'UPDATE `attributes` SET `sharing_group_id` = 0 WHERE `distribution` != 4';
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
		if (!isset($sqlArray)) $sqlArray = array($sql);
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
		if ($clean) $this->cleanCacheFiles();
		return true;
	}

	private function __dropIndex($table, $field) {
		$this->Log = ClassRegistry::init('Log');
		$indexCheck = "SELECT INDEX_NAME FROM INFORMATION_SCHEMA.STATISTICS WHERE table_schema=DATABASE() AND table_name='" . $table . "' AND index_name LIKE '" . $field . "%'";
		$indexCheckResult = $this->query($indexCheck);
		foreach ($indexCheckResult as $icr) {
			$dropIndex = 'ALTER TABLE ' . $table . ' DROP INDEX ' . $icr['STATISTICS']['INDEX_NAME'];
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

	public function cleanCacheFiles() {
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

	public function checkMISPVersion() {
		App::uses('Folder', 'Utility');
		$file = new File(ROOT . DS . 'VERSION.json', true);
		$version_array = json_decode($file->read(), true);
		$file->close();
		return $version_array;
	}

	// wrapper for UUID generation, compatible with cakephp <= 2.6 and cakephp and cakephp >= 2.7
	public function generateUuid() {
		$version = Configure::version();
		$version = explode('.', $version);
		if (intval($version[0]) <= 2 && intval($version[1]) < 7) $uuid = String::uuid();
		else $uuid = CakeText::uuid();
		return $uuid;
	}

	// alternative to the build in notempty/notblank validation functions, compatible with cakephp <= 2.6 and cakephp and cakephp >= 2.7
	public function valueNotEmpty($value) {
		$field = array_keys($value);
		$field = $field[0];
		$value[$field] = trim($value[$field]);
		if (!empty($value[$field])) return true;
		return ucfirst($field) . ' cannot be empty.';
	}
	
	public function valueIsID($value) {
		$field = array_keys($value);
		$field = $field[0];
		if (!is_numeric($value[$field]) || $value[$field] < 0) 'Invalid ' . ucfirst($field) . ' ID';
		return true;
	}

	public function stringNotEmpty($value) {
		$field = array_keys($value);
		$field = $field[0];
		$value[$field] = trim($value[$field]);
		if (!isset($value[$field]) || ($value[$field] == false && $value[$field] !== "0")) return ucfirst($field) . ' cannot be empty.';
		return true;
	}

	public function runUpdates() {
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
			$db_version = $this->AdminSetting->find('first', array('conditions' => array('setting' => 'db_version')));
			$updates = $this->__findUpgrades($db_version['AdminSetting']['value']);
			if (!empty($updates)) {
				foreach ($updates as $update => $temp) {
					$this->updateMISP($update);
					if ($temp) $requiresLogout = true;
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

	private function __queueCleanDB() {
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

	private function __runCleanDB() {
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

	private function __findUpgrades($db_version) {
		$version = explode('.', $db_version);
		$updates = array();
		foreach ($this->db_changes as $major => $rest) {
			if ($major < $version[0]) continue;
			else if ($major == $version[0]) {
				foreach ($rest as $minor => $hotfixes) {
					if ($minor < $version[1]) continue;
					else if ($minor == $version[1]) {
						foreach ($hotfixes as $hotfix => $requiresLogout) if ($hotfix > $version[2]) $updates[$major . '.' . $minor . '.' . $hotfix] = $requiresLogout;
					} else {
						foreach ($hotfixes as $hotfix => $requiresLogout) $updates[$major . '.' . $minor . '.' . $hotfix] = $requiresLogout;
					}
				}
			} else {
				// we'll fill this out when 3.0 comes around
			}
		}
		return $updates;
	}


	public function populateNotifications($user) {
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


	private function _getProposalCount($user) {
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
			if (!in_array($sa['ShadowAttribute']['event_id'], $eventIds)) $eventIds[] = $sa['ShadowAttribute']['event_id'];
		}
		$results[1] = count($eventIds);
		return $results;
	}

	private function _getDelegationCount($user) {
		$this->EventDelegation = ClassRegistry::init('EventDelegation');
		$delegations = $this->EventDelegation->find('count', array(
				'recursive' => -1,
				'conditions' => array(
						'EventDelegation.org_id' => $user['org_id']
				)
		));
		return $delegations;
	}
}
