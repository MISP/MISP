<?php
App::uses('JSONConverterTool', 'Tools');
App::uses('TmpFileTool', 'Tools');

abstract class StixExport
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
    /** @var TmpFileTool */
    private $__stix_file;
    /** @var File */
    private $__tmp_file = null;
    private $__n_attributes = 0;

    public $non_restrictive_export = true;
    public $use_default_filters = true;

    private $Server;

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

        $converter = new JSONConverterTool();
        $event = json_encode($converter->convert($data, false, true)); // we don't need pretty printed JSON
        if ($this->__n_attributes + $attributes_count < $this->__attributes_limit) {
            $this->__tmp_file->append($this->__n_attributes === 0 ? $event : ',' . $event);
            $this->__n_attributes += $attributes_count;
            $this->__empty_file = false;
        } elseif  ($attributes_count > $this->__attributes_limit) {
            $randomFileName = $this->__generateRandomFileName();
            FileAccessTool::writeToFile($this->__tmp_dir . $randomFileName, $event);
            $this->__filenames[] = $randomFileName;
        } else {
            $this->__tmp_file->append(']}');
            $this->__tmp_file->close();
            $this->__filenames[] = $this->__current_filename;
            $this->__initialize_misp_file();
            $this->__tmp_file->append($event);
            $this->__n_attributes = $attributes_count;
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
        $this->__framing = json_decode(shell_exec($framing_cmd), true);
        $this->__stix_file = new TmpFileTool();
        $this->__stix_file->write($this->__framing['header']);
        $this->__initialize_misp_file();
        return '';
    }

    /**
     * @return string|TmpFileTool
     * @throws Exception
     */
    public function footer()
    {
        if ($this->__empty_file) {
            $this->__tmp_file->close();
            $this->__tmp_file->delete();
        } else {
            $this->__tmp_file->append(']}');
            $this->__tmp_file->close();
            $this->__filenames[] = $this->__current_filename;
        }
        $filenames = implode(' ' . $this->__tmp_dir, $this->__filenames);
        $result = $this->__parse_misp_events($filenames);
        $decoded = json_decode($result, true);
        if (!isset($decoded['success']) || !$decoded['success']) {
            $this->__delete_temporary_files();
            $error = $decoded && !empty($decoded['error']) ? $decoded['error'] : $result;
            return 'Error while processing your query: ' . $error;
        }
        foreach ($this->__filenames as $filename) {
            $stix_event = FileAccessTool::readFromFile($this->__tmp_dir . $filename . '.out');
            $stix_event = $this->__return_type === 'stix' ? $stix_event : substr($stix_event, 1, -1);
            FileAccessTool::deleteFile($this->__tmp_dir . $filename . '.out');
            $this->__stix_file->writeWithSeparator($stix_event, $this->__framing['separator']);
        }

        $this->__stix_file->write($this->__framing['footer']);
        return $this->__stix_file;
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
        foreach ($this->__filenames as $filename) {
            @unlink($this->__tmp_dir . $filename);
        }
    }

    /**
     * @return string
     */
    protected function pythonBin()
    {
        if (!isset($this->Server)) {
            $this->Server = ClassRegistry::init('Server');
        }
        return $this->Server->getPythonVersion();
    }

    abstract protected function __parse_misp_events($filenames);

    abstract protected function __initiate_framing_params();
}
