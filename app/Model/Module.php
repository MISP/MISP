<?php
App::uses('AppModel', 'Model');

class Module extends AppModel {
	public $useTable = false;


	public function getModules($type = false) {
		$modules = $this->queryModuleServer('/modules');
		if (!$modules) return 'Module service not reachable.';
		if (!empty($modules)) {
			$result = array('modules' => $modules);
			return $result;
		} else return 'The module service reports that it found no modules.';
	}
	
	public function getEnabledModules($type = false) {
		$modules = $this->getModules($type);
		if (is_array($modules)) {
			foreach ($modules['modules'] as $k => &$module) {
				if (!Configure::read('Plugin.Enrichment_' . $module['name'] . '_enabled') || ($type && in_array($type, $module['meta']['module-type']))) {
					unset($modules['modules'][$k]);
				}
			}
		} else return 'The modules system reports that it found no suitable modules.';
		if (!isset($modules) || empty($modules)) $modules = array();
		if (isset($modules['modules']) && !empty($modules['modules'])) $modules['modules'] = array_values($modules['modules']);
		if (!is_array($modules)) return array();
		foreach ($modules['modules'] as $temp) {
			if (isset($temp['meta']['module-type']) && in_array('import', $temp['meta']['module-type']))  $modules['import'] = $temp['name'];
			else if (isset($temp['meta']['module-type']) && in_array('export', $temp['meta']['module-type']))  $modules['export'] = $temp['name'];
			else {
				foreach ($temp['mispattributes']['input'] as $input) {
					if (!isset($temp['meta']['module-type']) || in_array('expansion', $temp['meta']['module-type'])) $modules['types'][$input][] = $temp['name'];
					if (isset($temp['meta']['module-type']) && in_array('hover', $temp['meta']['module-type']))  $modules['hover_type'][$input][] = $temp['name'];
				}
			}
		}
		return $modules;
	}
	
	private function __getModuleServer() {
		$this->Server = ClassRegistry::init('Server');
		if (!Configure::read('Plugin.Enrichment_services_enable')) return false;
		$url = Configure::read('Plugin.Enrichment_services_url') ? Configure::read('Plugin.Enrichment_services_url') : $this->Server->serverSettings['Plugin']['Enrichment_services_url']['value'];
		$port = Configure::read('Plugin.Enrichment_services_port') ? Configure::read('Plugin.Enrichment_services_port') : $this->Server->serverSettings['Plugin']['Enrichment_services_port']['value'];
		return $url . ':' . $port;
	}
	
	public function queryModuleServer($uri, $post = false) {
		$url = $this->__getModuleServer();
		if (!$url) return false;
		App::uses('HttpSocket', 'Network/Http');
		$httpSocket = new HttpSocket();
		try {
			if ($post) $response = $httpSocket->post($url . $uri, $post);
			else $response = $httpSocket->get($url . $uri);
			return json_decode($response->body, true);
		} catch (Exception $e) {
			return false;
		}
	}
	
	public function getModuleSettings() {
		$modules = $this->getModules();
		$result = array();
		if (!empty($modules['modules'])) {
			foreach ($modules['modules'] as $module) {
				$result[$module['name']][0] = array('name' => 'enabled', 'type' => 'boolean');
				if (isset($module['meta']['config'])) foreach ($module['meta']['config'] as $conf) $result[$module['name']][] = array('name' => $conf, 'type' => 'string');
			}
		}
		return $result;
	}
}
