<?php

class StixExport
{
    public $additional_params = array(
        'includeEventTags' => 1,
        'includeGalaxy' => 1
    );
    protected $__return_format = 'json';
    protected $__scripts_dir = APP . 'files/scripts/';
    protected $__tmp_dir = APP . 'files/scripts/tmp/';
    protected $__framing_script = APP . 'files/scripts/misp_framing.py';
    protected $__end_of_cmd = ' 2>' . APP . 'tmp/logs/exec-errors.log';
    protected $__return_type = null;
    protected $__filenames = array();
    protected $__default_filters = null;
    protected $__version = null;

    private $__current_filename = null;
    private $__empty_file = null;
    private $__framing = null;
    private $__stix_file = null;
    private $__tmp_file = null;
    private $__n_attributes = 0;

    public $non_restrictive_export = true;
    public $use_default_filters = true;

    public function setDefaultFilters($filters)
    {
        $sane_version = (!empty($filters['stix-version']) && in_array($filters['stix-version'], $this->__sane_versions));
        $this->__version = $sane_version ? $filters['stix-version'] : $this->__default_version;
    }

    public function handler($data, $options = array())
    {
        $attributes_count = count($data['Attribute']);
        foreach ($data['Object'] as $_object) {
            if (isset($_object['Attribute'])) {
                $attributes_count += count($_object['Attribute']);
            }
        }
        App::uses('JSONConverterTool', 'Tools');
        $converter = new JSONConverterTool();
        $event = $converter->convert($data);
        if ($this->__n_attributes + $attributes_count < $this->__attributes_limit) {
            $this->__tmp_file->append($this->__n_attributes == 0 ? $event : ',' . $event);
            $this->__n_attributes += $attributes_count;
            $this->__empty_file = false;
        } else {
            if ($attributes_count > $this->__attributes_limit) {
                $randomFileName = $this->__generateRandomFileName();
                $tmpFile = new File($this->__tmp_dir . $randomFileName, true, 0644);
                $tmpFile->write($event);
                $tmpFile->close();
                array_push($this->__filenames, $randomFileName);
            } else {
                $this->__tmp_file->append(']}');
                $this->__tmp_file->close();
                array_push($this->__filenames, $this->__current_filename);
                $this->__initialize_misp_file();
                $this->__tmp_file->append($event);
                $this->__n_attributes = $attributes_count;
            }
        }
        return '';
    }

    public function header($options = array())
    {
        $this->__return_type = $options['returnFormat'];
        if ($this->__return_type == 'stix-json') {
            $this->__return_type = 'stix';
        } else if ($this->__return_type == 'stix') {
            $this->__return_format = 'xml';
        }
        $framing_cmd = $this->__initiate_framing_params();
        $randomFileName = $this->__generateRandomFileName();
        $this->__framing = json_decode(shell_exec($framing_cmd), true);
        $this->__stix_file = new File($this->__tmp_dir . $randomFileName . '.' . $this->__return_type);
        unset($randomFileName);
        $this->__stix_file->write($this->__framing['header']);
        $this->__initialize_misp_file();
        return '';
    }

    public function footer()
    {
        if ($this->__empty_file) {
            $this->__tmp_file->close();
            $this->__tmp_file->delete();
        } else {
            $this->__tmp_file->append(']}');
            $this->__tmp_file->close();
            array_push($this->__filenames, $this->__current_filename);
        }
        $filenames = implode(' ' . $this->__tmp_dir, $this->__filenames);
        $result = $this->__parse_misp_events($filenames);
        $decoded = json_decode($result, true);
        if (!isset($decoded['success']) || !$decoded['success']) {
            $this->__delete_temporary_files();
            $error = $decoded && !empty($decoded['error']) ? $decoded['error'] : $result;
            return 'Error while processing your query: ' . $error;
        }
        foreach ($this->__filenames as $f => $filename) {
            $file = new File($this->__tmp_dir . $filename . '.out');
            $stix_event = ($this->__return_type == 'stix') ? $file->read() : substr($file->read(), 1, -1);
            $file->close();
            $file->delete();
            @unlink($this->__tmp_dir . $filename);
            $this->__stix_file->append($stix_event . $this->__framing['separator']);
            unset($stix_event);
        }
        $stix_event = $this->__stix_file->read();
        $this->__stix_file->close();
        $this->__stix_file->delete();
        $sep_len = strlen($this->__framing['separator']);
        $stix_event = (empty($this->__filenames) ? $stix_event : substr($stix_event, 0, -$sep_len)) . $this->__framing['footer'];
        return $stix_event;
    }

    public function separator()
    {
        return '';
    }

    private function __initialize_misp_file()
    {
        $this->__current_filename = $this->__generateRandomFileName();
        $this->__tmp_file = new File($this->__tmp_dir . $this->__current_filename, true, 0644);
        $this->__tmp_file->write('{"response": [');
        $this->__empty_file = true;
    }

    private function __generateRandomFileName()
    {
        return (new RandomTool())->random_str(false, 12);
    }

    private function __delete_temporary_files()
    {
        foreach ($this->__filenames as $f => $filename) {
            @unlink($this->__tmp_dir . $filename);
        }
        $this->__stix_file->close();
        $this->__stix_file->delete();
    }
}
