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
			case 'addEventBlacklistsContext':
				$sql = 'ALTER TABLE  `event_blacklists` ADD  `event_orgc` VARCHAR( 255 ) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL , ADD  `event_info` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL, ADD `comment` TEXT CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL ;';
				break;
			case 'addSightings':
				$sql = "CREATE TABLE IF NOT EXISTS `sightings` (
				`id` int(11) NOT NULL AUTO_INCREMENT,
				`attribute_id` int(11) NOT NULL,
				`event_id` int(11) NOT NULL,
				`org_id` int(11) NOT NULL,
				`date_sighting` datetime NOT NULL,
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
			case 'addIPLogging':
				$sql = 'ALTER TABLE `logs` ADD  `ip` varchar(45) COLLATE utf8_bin DEFAULT NULL;';
				break;
			case '24betaupdates':
				$sqlArray = array();
				$sqlArray[] = 'ALTER TABLE `shadow_attributes` ADD  `proposal_to_delete` BOOLEAN NOT NULL';
				
				$sqlArray[] = 'ALTER TABLE `logs` MODIFY  `change` text COLLATE utf8_bin NOT NULL';
				
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
					'attributes' => array(array('value1', 'FULLTEXT'), array('value2', 'FULLTEXT'), array('event_id', 'INDEX'), array('sharing_group_id', 'INDEX'), array('uuid', 'INDEX')),
					'correlations' =>  array(array('org_id', 'INDEX'), array('event_id', 'INDEX'), array('attribute_id', 'INDEX'), array('sharing_group_id', 'INDEX'), array('1_event_id', 'INDEX'), array('1_attribute_id', 'INDEX'), array('a_sharing_group_id', 'INDEX'), array('org_id', 'INDEX'), array('value', 'FULLTEXT')),
					'events' => array(array('info', 'FULLTEXT'), array('sharing_group_id', 'INDEX'), array('org_id', 'INDEX'), array('orgc_id', 'INDEX'), array('uuid', 'INDEX')),
					'event_tags' => array(array('event_id', 'INDEX'), array('tag_id', 'INDEX')),
					'organisations' => array(array('uuid', 'INDEX'), array('name', 'FULLTEXT')),
					'posts' => array(array('post_id', 'INDEX'), array('thread_id', 'INDEX')),
					'shadow_attributes' => array(array('value1', 'FULLTEXT'), array('value2', 'FULLTEXT'), array('old_id', 'INDEX'), array('event_id', 'INDEX'), array('uuid', 'INDEX'), array('event_org_id', 'INDEX'), array('event_uuid', 'INDEX')),
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
						$sqlArray[] = 'ALTER TABLE `' . $table . '` ADD ' . ($downgradeThis ? 'INDEX' : $field[1]) . ' `' . $field[0] . '` (`' . $field[0] . '`)';
					}
				}
				break;
			case 'fixNonEmptySharingGroupID':
				$sqlArray[] = 'UPDATE `events` SET `sharing_group_id` = 0 WHERE `distribution` != 4';
				$sqlArray[] = 'UPDATE `attributes` SET `sharing_group_id` = 0 WHERE `distribution` != 4';
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
		$directories = array(APP . '/tmp/cache/models', APP . '/tmp/cache/persistent');
		foreach ($directories as $directory) {
			$dir = new Folder($directory);
			$files = $dir->find('myapp.*');
			foreach ($files as $file) {
				$file = new File($dir->path . DS . $file);
				$file->delete();
				$file->close();
			}
		}
	}
	
	public function checkMISPVersion() {
		App::uses('Folder', 'Utility');
		$file = new File (ROOT . DS . 'VERSION.json', true);
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
}
