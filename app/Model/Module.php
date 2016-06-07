<?php
App::uses('AppModel', 'Model');

class Module extends AppModel {
	public $useTable = false;


	public function getEnrichmentModules() {
		if (!Configure::read('Plugin.Enrichment_services_enable')) return 'Enrichment service not enabled.';
		$url = Configure::read('Plugin.Enrichment_services_url') ? Configure::read('Plugin.Enrichment_services_url') : $this->serverSettings['Plugin']['Enrichment_services_url']['value'];
		$port = Configure::read('Plugin.Enrichment_services_port') ? Configure::read('Plugin.Enrichment_services_port') : $this->serverSettings['Plugin']['Enrichment_services_port']['value'];
		App::uses('HttpSocket', 'Network/Http');
		$httpSocket = new HttpSocket();
		try {
			$response = $httpSocket->get($url . ':' . $port . '/modules');
		} catch (Exception $e) {
			return 'Enrichment service not reachable.';
		}
		$modules = json_decode($response->body, true);
		if (!empty($modules)) {
			$result = array('modules' => $modules);
			foreach ($modules as &$module) {
				if ($module['type'] !== 'expansion') continue;
				foreach ($module['mispattributes']['input'] as $attribute) {
					$result['types'][$attribute][] = $module['name'];
				}
			}
			return $result;
		} else return 'The enrichment service reports that it found no enrichment modules.';
	}

	public function getEnabledModules() {
		$modules = $this->getEnrichmentModules();
		if (is_array($modules)) {
			foreach ($modules['modules'] as $k => &$module) {
				if (!Configure::read('Plugin.Enrichment_' . $module['name'] . '_enabled')) {
					unset($modules['modules'][$k]);
				}
			}
		}
		if (!isset($modules) || empty($modules)) $modules = array();
		if (isset($modules['modules']) && !empty($modules['modules'])) $modules['modules'] = array_values($modules['modules']);
		$types = array();
		$hover_types = array();
		if (!is_array($modules)) return array();
		foreach ($modules['modules'] as $temp) {
			foreach ($temp['mispattributes']['input'] as $input) {
				if (!isset($temp['meta']['module-type']) || in_array('expansion', $temp['meta']['module-type'])) $types[$input][] = $temp['name'];
				if (isset($temp['meta']['module-type']) && in_array('hover', $temp['meta']['module-type'])) $hover_types[$input][] = $temp['name'];
			}
		}
		$modules['types'] = $types;
		$modules['hover_type'] = $hover_types;
		return $modules;
	}

	public function sendRequest() {

	}

	public function queryModule() {

	}

	private function queryModule() {

	}
}
