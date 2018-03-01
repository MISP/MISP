<?php
App::uses('AppModel', 'Model');

class Module extends AppModel {

	public $useTable = false;

	private $__validTypes = array(
		'Enrichment' => array('hover', 'expansion'),
		'Import' => array('import'),
		'Export' => array('export'),
		'Cortex' => array('cortex')
	);

	private $__typeToFamily = array(
		'Import' => 'Import',
		'Export' => 'Export',
		'hover' => 'Enrichment',
		'expansion' => 'Enrichment',
		'Cortex' => 'Cortex'
	);

	public $configTypes = array(
		'IP' => array(
			'validation' => 'validateIPField',
			'field' => 'text',
			'class' => 'input-xxlarge'
		),
		'String' => array(
			'validation' => 'validateStringField',
			'field' => 'text',
			'class' => 'input-xxlarge'
		),
		'Integer' => array(
			'validation' => 'validateIntegerField',
			'field' => 'number',
		),
		'Boolean' => array(
			'validation' => 'validateBooleanField',
			'field' => 'checkbox'
		),
		'Select' => array(
			'validation' => 'validateSelectField',
			'field' => 'select'
		)
	);

	public function validateIPField($value) {
		if (!filter_var($value, FILTER_VALIDATE_IP) === false) {
			return 'Value is not a valid IP.';
		}
		return true;
	}

	public function validateStringField($value) {
		if (!empty($value)) return true;
		return 'Field cannot be empty.';
	}

	public function validateIntegerField($value) {
		if (is_numeric($value) && is_int(intval($value))) {
			return true;
		}
		return 'Value is not an integer.';
	}

	public function validateBooleanField($value) {
		if ($value == true || $value == false) {
			return true;
		}
		return 'Value has to be a boolean.';
	}


	public function getModules($type = false, $moduleFamily = 'Enrichment', &$exception = false) {
		$modules = $this->queryModuleServer('/modules', false, false, $moduleFamily, $exception);
		if (!$modules) return 'Module service not reachable.';
		if (!empty($modules)) {
			$result = array('modules' => $modules);
			return $result;
		} else return 'The module service reports that it found no modules.';
	}

	public function getEnabledModules($user, $type = false, $moduleFamily = 'Enrichment') {
		$modules = $this->getModules($type, $moduleFamily);
		if (is_array($modules)) {
			foreach ($modules['modules'] as $k => $module) {
				if (!Configure::read('Plugin.' . $moduleFamily . '_' . $module['name'] . '_enabled') || ($type && in_array(strtolower($type), $module['meta']['module-type']))) {
					unset($modules['modules'][$k]);
					continue;
				}
				if (
					!$user['Role']['perm_site_admin'] &&
					Configure::read('Plugin.' . $moduleFamily . '_' . $module['name'] . '_restrict') &&
					Configure::read('Plugin.' . $moduleFamily . '_' . $module['name'] . '_restrict') != $user['org_id']
				) {
					unset($modules['modules'][$k]);
				}
			}
		} else return 'The modules system reports that it found no suitable modules.';
		if (!isset($modules) || empty($modules)) $modules = array();
		if (isset($modules['modules']) && !empty($modules['modules'])) $modules['modules'] = array_values($modules['modules']);
		if (!is_array($modules)) return array();
		foreach ($modules['modules'] as $temp) {
			if (isset($temp['meta']['module-type']) && in_array('import', $temp['meta']['module-type']))  $modules['Import'] = $temp['name'];
			else if (isset($temp['meta']['module-type']) && in_array('export', $temp['meta']['module-type']))  $modules['Export'] = $temp['name'];
			else {
				foreach ($temp['mispattributes']['input'] as $input) {
					if (!isset($temp['meta']['module-type']) || (in_array('expansion', $temp['meta']['module-type']) || in_array('cortex', $temp['meta']['module-type']))) $modules['types'][$input][] = $temp['name'];
					if (isset($temp['meta']['module-type']) && in_array('hover', $temp['meta']['module-type']))  $modules['hover_type'][$input][] = $temp['name'];
				}
			}
		}
		return $modules;
	}

	public function getEnabledModule($name, $type) {
		$moduleFamily = $this->__typeToFamily[$type];
		$url = $this->__getModuleServer($moduleFamily);
		$modules = $this->getModules($type, $moduleFamily);
		$module = false;
		if (!Configure::read('Plugin.' . $moduleFamily . '_' . $name . '_enabled')) return 'The requested module is not enabled.';
		if (is_array($modules)) {
			foreach ($modules['modules'] as $module) {
				if ($module['name'] == $name) {
					if ($type && in_array(strtolower($type), $module['meta']['module-type'])) {
						return $module;
					} else {
						return 'The requested module is not available for the requested action.';
					}
				}
			}
		} else return $modules;
		return 'The modules system reports that it found no suitable modules.';
	}

	private function __getModuleServer($moduleFamily = 'Enrichment') {
		if (!Configure::read('Plugin.' . $moduleFamily . '_services_enable')) return false;
		$this->Server = ClassRegistry::init('Server');
		$url = Configure::read('Plugin.' . $moduleFamily . '_services_url') ? Configure::read('Plugin.' . $moduleFamily . '_services_url') : $this->Server->serverSettings['Plugin'][$moduleFamily . '_services_url']['value'];
		$port = Configure::read('Plugin.' . $moduleFamily . '_services_port') ? Configure::read('Plugin.' . $moduleFamily . '_services_port') : $this->Server->serverSettings['Plugin'][$moduleFamily . '_services_port']['value'];
		return $url . ':' . $port;
	}

	public function queryModuleServer($uri, $post = false, $hover = false, $moduleFamily = 'Enrichment', &$exception = false) {
		$url = $this->__getModuleServer($moduleFamily);
		if (!$url) return false;
		App::uses('HttpSocket', 'Network/Http');
		if ($hover) {
			$httpSocket = new HttpSocket(array('timeout' => Configure::read('Plugin.' . $moduleFamily . '_hover_timeout') ? Configure::read('Plugin.' . $moduleFamily . '_hover_timeout') : 5));
		} else {
			$httpSocket = new HttpSocket(array('timeout' => Configure::read('Plugin.' . $moduleFamily . '_timeout') ? Configure::read('Plugin.' . $moduleFamily . '_timeout') : 10));
		}
		$request = array(
				'header' => array(
						'Content-Type' => 'application/json',
				)
		);
		try {
			if ($post) $response = $httpSocket->post($url . $uri, $post, $request);
			else $response = $httpSocket->get($url . $uri);
			return json_decode($response->body, true);
		} catch (Exception $e) {
			$exception = $e->getMessage();
			return false;
		}
	}

	public function getModuleSettings($moduleFamily = 'Enrichment') {
		$modules = $this->getModules(false, $moduleFamily);
		$result = array();
		if (!empty($modules['modules'])) {
			foreach ($modules['modules'] as $module) {
				if (array_intersect($this->__validTypes[$moduleFamily], $module['meta']['module-type'])) {
					$result[$module['name']][0] = array('name' => 'enabled', 'type' => 'boolean');
					$result[$module['name']][1] = array('name' => 'restrict', 'type' => 'orgs');
					if (isset($module['meta']['config'])) foreach ($module['meta']['config'] as $conf) $result[$module['name']][] = array('name' => $conf, 'type' => 'string');
				}
			}
		}
		return $result;
	}
}
