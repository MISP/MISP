<?php
App::uses('JSONConverterTool', 'Tools');
App::uses('TmpFileTool', 'Tools');
App::uses('JsonTool', 'Tools');
App::uses('ProcessTool', 'Tools');

abstract class StixExport
{
    public $additional_params = array(
        'includeEventTags' => 1,
        'includeGalaxy' => 1
    );
    protected $__return_format = 'json';
    protected $__scripts_dir = APP . 'files/scripts/';
    protected $__framing_script = APP . 'files/scripts/misp_framing.py';
    protected $__return_type = null;

    /** @var array Full paths to files to convert */
    protected $__filenames = array();
    protected $__version = null;

    private $__current_filename = null;
    private $__empty_file = null;
    /** @var File */
    private $__tmp_file = null;
    private $__n_attributes = 0;

    public $non_restrictive_export = true;

    private $Server;

    public function setDefaultFilters($filters)
    {
        $sane_version = !empty($filters['stix-version']) && in_array($filters['stix-version'], $this->__sane_versions, true);
        $this->__version = $sane_version ? $filters['stix-version'] : $this->__default_version;
    }

    public function handler($data, $options = array())
    {
        $attributesCount = count($data['Attribute']);
        foreach ($data['Object'] as $object) {
            if (isset($object['Attribute'])) {
                $attributesCount += count($object['Attribute']);
            }
        }

        $converter = new JSONConverterTool();
        $event = JsonTool::encode($converter->convert($data, false, true)); // we don't need pretty printed JSON
        if ($this->__n_attributes + $attributesCount < $this->__attributes_limit) {
            $this->__tmp_file->append($this->__n_attributes === 0 ? $event : ',' . $event);
            $this->__n_attributes += $attributesCount;
            $this->__empty_file = false;
        } elseif  ($attributesCount > $this->__attributes_limit) {
            $filePath = FileAccessTool::writeToTempFile($event);
            $this->__filenames[] = $filePath;
        } else {
            $this->__tmp_file->append(']}');
            $this->__tmp_file->close();
            $this->__filenames[] = $this->__current_filename;
            $this->__initialize_misp_file();
            $this->__tmp_file->append($event);
            $this->__n_attributes = $attributesCount;
        }
        return '';
    }

    public function header($options = array())
    {
        $this->__return_type = $options['returnFormat'];
        if ($this->__return_type === 'stix-json') {
            $this->__return_type = 'stix';
        } else if ($this->__return_type === 'stix') {
            $this->__return_format = 'xml';
        }
        $this->__initialize_misp_file();
        return '';
    }

    /**
     * @return TmpFileTool
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
        $result = $this->__parse_misp_events($this->__filenames);
        $this->__delete_temporary_files();
        $decoded = json_decode($result, true);
        if (!isset($decoded['success']) || !$decoded['success']) {
            $error = $decoded && !empty($decoded['error']) ? $decoded['error'] : $result;
            throw new Exception('Error while processing your query during STIX export: ' . $error);
        }

        $framing = $this->getFraming();

        $stixFile = new TmpFileTool();
        $stixFile->write($framing['header']);
        foreach ($this->__filenames as $filename) {
            $stixEvent = FileAccessTool::readAndDelete($filename . '.out');
            $stixEvent = $this->__return_type === 'stix' ? $stixEvent : substr($stixEvent, 1, -1);
            $stixFile->writeWithSeparator($stixEvent, $framing['separator']);
        }
        $stixFile->write($framing['footer']);
        return $stixFile;
    }

    public function separator()
    {
        return '';
    }

    private function __initialize_misp_file()
    {
        $this->__current_filename = FileAccessTool::createTempFile();
        $this->__tmp_file = new File($this->__current_filename);
        $this->__tmp_file->write('{"response": [');
        $this->__empty_file = true;
    }

    private function __delete_temporary_files()
    {
        foreach ($this->__filenames as $filename) {
            FileAccessTool::deleteFileIfExists($filename);
        }
    }

    /**
     * @return array
     * @throws Exception
     */
    private function getFraming()
    {
        $framingCmd = $this->__initiate_framing_params();
        $framing = json_decode(ProcessTool::execute($framingCmd, null, true), true);
        if ($framing === null || isset($framing['error'])) {
            throw new Exception("Could not get results from framing cmd when exporting STIX file.");
        }
        return $framing;
    }

    /**
     * @param array $filenames Paths to files to process
     * @return string|false|null
     */
    abstract protected function __parse_misp_events(array $filenames);

    /**
     * @return array
     */
    abstract protected function __initiate_framing_params();
}
