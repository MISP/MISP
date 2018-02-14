<?php
App::uses('AppController', 'Controller');
class ModulesQueryController extends AppController {

    public $components = array(
        'Security', 
        'RequestHandler'
    );
    
	public $paginate = array(
			'limit' => 60,
    );
    
	public function query() {
        // Initialize models
        $this->loadModel('Server');
        $this->loadModel('Module');
        $modules = $this->Module->getEnabledModules($this->Auth->user());

        // Prepare input
        $url = Configure::read('Plugin.Enrichment_services_url') ? Configure::read('Plugin.Enrichment_services_url') : $this->Server->serverSettings['Plugin']['Enrichment_services_url']['value'];
        $port = Configure::read('Plugin.Enrichment_services_port') ? Configure::read('Plugin.Enrichment_services_port') : $this->Server->serverSettings['Plugin']['Enrichment_services_port']['value'];
        $data = $this->request->data;
        $modname = $data['module'];
        $options = array();

        // Support credentials
        foreach ($modules['modules'] as $temp) {
            if ($temp['name'] == $modname) {
                if (isset($temp['meta']['config'])) {
                    foreach ($temp['meta']['config'] as $conf) $options[$conf] = Configure::read('Plugin.Enrichment_' . $modname . '_' . $conf);
                }
                break;
            }
        }
        if (!empty($options)) $data['config'] = $options;

        // Query
        $result = $this->Module->queryModuleServer('/query', json_encode($data), true);
        if ($result) {
            $result = json_decode('{"error": "Something went wrong, no response from module."}');
        }

        // Set output
        $this->set('results', json_encode($result));
        $this->layout = 'ajax';
    };

	public function index() {
        // Initialize models
		$this->loadModel('Module');
		$modules = $this->Module->getEnabledModules($this->Auth->user());
        
        // Query
        $result = $this->Module->queryModuleServer('/modules', false, true);
        if ($result) {
            $result = json_decode('{"error": "Something went wrong, no response from misp_modules."}');
        }
        
        // Set output
        $this->set('results', json_encode($result));
		$this->layout = 'ajax';
	};
}
