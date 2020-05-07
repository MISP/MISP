<?php

class OpendataExport
{
    public $non_restrictive_export = true;
    public $use_default_filters = true;
    private $__default_filters = null;

    private $__auth = null;
    private $__delete = false;
    private $__scope = null;
    private $__setup = array();
    private $__url = null;

    private $__scripts_dir = APP . 'files/scripts/';
    private $__script_name = 'misp-opendata/opendata.py';

    public function setDefaultFilters($filters)
    {
        $this->__default_filters = $filters;
    }

    public function header($options = array())
    {
        $this->__scope = $options['scope'];
        if (isset($this->__default_filters['auth'])) {
            $this->__auth = $this->__default_filters['auth'];
            unset($this->__default_filters['auth']);
        }
        if (isset($this->__default_filters['setup'])) {
            $this->__setup = $this->__default_filters['setup'];
            unset($this->__default_filters['setup']);
        }
        if (isset($this->__default_filters['url'])) {
            $this->__url = $this->__default_filters['url'];
            unset($this->__default_filters['url']);
        } else {
            $baseurl = Configure::read('MISP.baseurl');
            if (empty($baseurl)) {
                throw new Exception('Missing url of the MISP instance, and baseurl is not set.');
            }
            $this->__url = $baseurl;
        }
        if (!empty($this->__default_filters['delete'])) {
            $this->__delete = true;
            unset($this->__default_filters['delete']);
        }
        return '';
    }

    public function footer()
    {
        $authParam = ' --auth ' . $this->__auth;
        $my_server = ClassRegistry::init('Server');
        $cmd = $my_server->getPythonVersion() . ' ' . $this->__scripts_dir . $this->__script_name . $authParam;
        return $this->__delete ? $this->__delete_query($cmd) : $this->__add_query($cmd);
    }

    public function handler()
    {
        return '';
    }

    public function separator()
    {
        return '';
    }

    private function __add_query($cmd)
    {
        $body = json_encode($this->__default_filters);
        $bodyFilename = $this->__generateSetupFile($body);
        $bodyParam = ' --body ' . $bodyFilename;
        $levelParam = ' --level ' . strtolower($this->__scope) . 's';
        $setup = json_encode($this->__setup);
        $setupFilename = $this->__generateSetupFile($setup);
        $setupParam = ' --setup ' . $setupFilename;
        $urlParam = ' --url ' . $this->__url;

        $cmd .= $bodyParam . $setupParam . $levelParam . $urlParam;
        $results = shell_exec($cmd);
        unlink($bodyFilename);
        unlink($setupFilename);
        return $results;
    }

    private function __delete_query($cmd)
    {
        $cmd .= " -d '" . $this->__setup['dataset'] . "'";
        if (!empty($this->__setup['resources'])) {
            if (is_array($this->__setup['resources'])) {
                foreach ($this->__setup['resources'] as $resource) {
                    $cmd .= ' ' . $resource;
                }
            } else {
                $cmd .= " '" . $this->__setup['resources'] . "'";
            }
        }
        return shell_exec($cmd);
    }

    private function __generateRandomFileName()
    {
        return (new RandomTool())->random_str(false, 12);
    }

    private function __generateSetupFile($to_write)
    {
        $filename = $this->__scripts_dir . 'tmp/' . $this->__generateRandomFileName();
        $tmpFile = new File($filename, true, 0644);
        $tmpFile->write($to_write);
        $tmpFile->close();
        return $filename;
    }
}
