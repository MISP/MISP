<?php
App::uses('AppController', 'Controller');
class ModulesController extends AppController {

    public $components = array(
        'Security', 
        'RequestHandler'
    );
    
    public function query() {
        // Prepare input
        $data = $this->request->data;
        $modname = $data['module'];
        $module = $this->Module->getEnabledModule($modname, 'hover');
        $options = array();
        
        // Check module
        if ($module['name'] != $modname) throw new MethodNotAllowedException('Module not found, or not allowed to use it.');
        if (isset($module['meta']['config'])) {
            foreach ($module['meta']['config'] as $conf) $options[$conf] = Configure::read('Plugin.Enrichment_' . $modname . '_' . $conf);
        }
        if (!empty($options)) $data['config'] = $options;
        
        // Query
        $result = $this->Module->queryModuleServer('/query', json_encode($data), true);
        if (!$result) {
            $result = array('error' => 'Something went wrong, no response from module.');
        }
        
        // Send output
        return $this->RestResponse->viewData($result);
    }
    
	public function index() {
        // Initialize models
		$modules = $this->Module->getEnabledModules($this->Auth->user());
        $result = array();
        
        // Prepare the result
        foreach ($modules['modules'] as $temp) {
            array_push($result, $temp);
        }
        
        if (!$result) {
            $result = array('error' => 'Something went wrong, no response from misp_modules.');
        }
        
        // Send output
        return $this->RestResponse->viewData($result);
	}
}