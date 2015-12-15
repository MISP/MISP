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
