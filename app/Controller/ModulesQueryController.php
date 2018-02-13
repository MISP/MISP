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
		$this->loadModel('Module');
		$modules = $this->Module->getEnabledModules($this->Auth->user());
        
        // Prepare input
        $data = $this->request->data;
        
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