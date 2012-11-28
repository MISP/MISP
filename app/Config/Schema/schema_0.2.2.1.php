<?php
class AppSchema extends CakeSchema {

	public $file = 'schema_0.2.2.1.php';

	public function before($event = array()) {
		return true;
	}

	public function after($event = array()) {
		if (isset($event['update'])) {
		        switch ($event['update']) {
		            case 'users':
		            	// TDDO Schema,Users.group_id is not here
        				break;
		        }
		}
	}

	public $attributes = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary'),
		'event_id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'index'),
		'category' => array('type' => 'string', 'null' => false, 'default' => NULL, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'type' => array('type' => 'string', 'null' => false, 'default' => NULL, 'length' => 100, 'collate' => 'utf8_unicode_ci', 'charset' => 'utf8'),
		'value1' => array('type' => 'text', 'null' => true, 'default' => NULL, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'value2' => array('type' => 'text', 'null' => true, 'default' => NULL, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'to_ids' => array('type' => 'boolean', 'null' => false, 'default' => '1'),
		'uuid' => array('type' => 'string', 'null' => false, 'default' => NULL, 'length' => 40, 'key' => 'index', 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'revision' => array('type' => 'integer', 'null' => false, 'default' => '0', 'length' => 10),
		'private' => array('type' => 'boolean', 'null' => false, 'default' => NULL),
		'cluster' => array('type' => 'boolean', 'null' => false, 'default' => NULL),
		'communitie' => array('type' => 'boolean', 'null' => false, 'default' => NULL),
		'indexes' => array('PRIMARY' => array('column' => 'id', 'unique' => 1), 'event_id' => array('column' => 'event_id', 'unique' => 0), 'uuid' => array('column' => 'uuid', 'unique' => 0)),
		'tableParameters' => array('charset' => 'utf8', 'collate' => 'utf8_bin', 'engine' => 'MyISAM')
	);
	public $bruteforces = array(
		'ip' => array('type' => 'string', 'null' => false, 'default' => NULL, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'username' => array('type' => 'string', 'null' => false, 'default' => NULL, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'expire' => array('type' => 'datetime', 'null' => false, 'default' => NULL),
		'indexes' => array(),
		'tableParameters' => array('charset' => 'utf8', 'collate' => 'utf8_bin', 'engine' => 'MyISAM')
	);
	public $correlations = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary'),
		'1_event_id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'index'),
		'1_attribute_id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'index'),
		'1_private' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
		'event_id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'index'),
		'attribute_id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'index'),
		'org' => array('type' => 'string', 'null' => false, 'default' => NULL, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'private' => array('type' => 'boolean', 'null' => false, 'default' => NULL),
		'cluster' => array('type' => 'boolean', 'null' => false, 'default' => NULL),
		'indexes' => array('PRIMARY' => array('column' => 'id', 'unique' => 1), 'uuid' => array('column' => 'uuid', 'unique' => 0), 'info' => array('column' => 'info', 'unique' => 0)),
		'tableParameters' => array('charset' => 'utf8', 'collate' => 'utf8_bin', 'engine' => 'MyISAM')
	);
	public $events = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary'),
		'org' => array('type' => 'string', 'null' => false, 'default' => NULL, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'date' => array('type' => 'date', 'null' => false, 'default' => NULL),
		//'risk' ENUM
		'info' => array('type' => 'text', 'null' => false, 'default' => NULL, 'key' => 'index', 'collate' => 'utf8_unicode_ci', 'charset' => 'utf8'),
		'user_id' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'published' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
		'uuid' => array('type' => 'string', 'null' => false, 'default' => NULL, 'length' => 40, 'key' => 'index', 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'revision' => array('type' => 'boolean', 'null' => false, 'default' => NULL),
		'private' => array('type' => 'boolean', 'null' => false, 'default' => NULL),
		'cluster' => array('type' => 'boolean', 'null' => false, 'default' => NULL),
		'communitie' => array('type' => 'boolean', 'null' => false, 'default' => NULL),
		'attribute_count' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'length' => 11),
		'hop_count' => array('type' => 'integer', 'null' => false, 'default' => '0', 'length' => 11),
		//'alerted' => array('type' => 'boolean', 'null' => false, 'default' => '0'),
		'indexes' => array('PRIMARY' => array('column' => 'id', 'unique' => 1), 'uuid' => array('column' => 'uuid', 'unique' => 0), 'info' => array('column' => 'info', 'unique' => 0)),
		'tableParameters' => array('charset' => 'utf8', 'collate' => 'utf8_bin', 'engine' => 'MyISAM')
	);
	public $servers = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary'),
		'url' => array('type' => 'string', 'null' => false, 'default' => NULL, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'authkey' => array('type' => 'string', 'null' => false, 'default' => NULL, 'length' => 40, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'org' => array('type' => 'string', 'null' => false, 'default' => NULL, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'organization' => array('type' => 'string', 'null' => false, 'default' => NULL, 'length' => 10, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'push' => array('type' => 'boolean', 'null' => false, 'default' => NULL),
		'pull' => array('type' => 'boolean', 'null' => false, 'default' => NULL),
		//'lastfetchedid' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'lastpulledid' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'lastpushedid' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'indexes' => array('PRIMARY' => array('column' => 'id', 'unique' => 1)),
		'tableParameters' => array('charset' => 'utf8', 'collate' => 'utf8_bin', 'engine' => 'MyISAM')
	);
	public $users = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary'),
		'password' => array('type' => 'string', 'null' => false, 'default' => NULL, 'length' => 40, 'key' => 'index', 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'org' => array('type' => 'string', 'null' => false, 'default' => NULL, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'email' => array('type' => 'string', 'null' => false, 'default' => NULL, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'autoalert' => array('type' => 'boolean', 'null' => false, 'default' => NULL),
		'authkey' => array('type' => 'string', 'null' => false, 'default' => NULL, 'length' => 40, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'invited_by' => array('type' => 'integer', 'null' => false, 'default' => NULL),
		'gpgkey' => array('type' => 'text', 'null' => false, 'default' => NULL, 'collate' => 'utf8_bin', 'charset' => 'utf8'),
		'nids_sid' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'length' => 15),
		'termsaccepted' => array('type' => 'boolean', 'null' => false, 'default' => NULL),
		'newsread' => array('type' => 'date', 'null' => false, 'default' => NULL),
		'group_id' => array('type' => 'integer', 'null' => true, 'default' => NULL),
		'indexes' => array('PRIMARY' => array('column' => 'id', 'unique' => 1), 'username' => array('column' => 'password', 'unique' => 0)),
		'tableParameters' => array('charset' => 'utf8', 'collate' => 'utf8_bin', 'engine' => 'MyISAM')
	);
	public $whitelists = array(
		'id' => array('type' => 'integer', 'null' => false, 'default' => NULL, 'key' => 'primary'),
		'name' => array('type' => 'text', 'null' => false, 'default' => NULL, 'key' => 'index', 'collate' => 'utf8_unicode_ci', 'charset' => 'utf8'),
		'indexes' => array('PRIMARY' => array('column' => 'id', 'unique' => 1)),
		'tableParameters' => array('charset' => 'utf8', 'collate' => 'utf8_bin', 'engine' => 'MyISAM')
	);
}
