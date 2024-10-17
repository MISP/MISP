<?php
App::uses('AppController', 'Controller');

/**
 * @property Module $Module
 */
class ModulesController extends AppController
{
    public $components = array(
        'RequestHandler'
    );

    public function queryEnrichment()
    {
        // Prepare input
        $data = $this->request->data;
        if (empty($data['module'])) {
            throw new MethodNotAllowedException('No module chosen. The request body has to have the module key set.');
        }
        $modname = $data['module'];
        $module = $this->Module->getEnabledModule($modname, 'hover');
        if (!Configure::read('Plugin.Enrichment_' . $modname . '_enabled')) {
            throw new MethodNotAllowedException('Module not found or not available.');
        }
        if (!$this->Module->canUse($this->Auth->user(), 'Enrichment', $module)) {
            throw new MethodNotAllowedException('Module not found or not available.');
        }
        $options = array();

        // Check module
        if ($module['name'] != $modname) {
            throw new MethodNotAllowedException('Module not found or not available.');
        }
        if (isset($module['meta']['config'])) {
            foreach ($module['meta']['config'] as $conf) {
                $options[$conf] = Configure::read('Plugin.Enrichment_' . $modname . '_' . $conf);
            }
        }
        if (!empty($options)) {
            $data['config'] = $options;
        }

        // Query
        $result = $this->Module->queryModuleServer($data, true);
        if (!$result) {
            $result = array('error' => 'Something went wrong, no response from module.');
        }

        // Send output
        return $this->RestResponse->viewData($result);
    }

    public function index()
    {
        // Initialize models
        $modules = $this->Module->getEnabledModules($this->Auth->user());
        $result = array();

        // Prepare the result
        foreach ($modules['modules'] as $temp) {
            // remove the config, don't want to accidentally leak api keys / credentials
            unset($temp['meta']['config']);
            array_push($result, $temp);
        }

        if (!$result) {
            $result = array('error' => 'Something went wrong, no response from misp_modules.');
        }

        // Send output
        return $this->RestResponse->viewData($result);
    }
}
