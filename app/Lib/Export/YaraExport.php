<?php
App::uses('JsonExport', 'Export');
App::uses('ProcessTool', 'Tools');
App::uses('TmpFileTool', 'Tools');

class YaraExport
{
    private $__script_path = APP . 'files/scripts/yara/yaraexport.py';
    private $__n_attributes = 0;
    private $__MAX_n_attributes = 15000;
    private $__yara_file_gen = null;
    private $__yara_file_asis = null;
    /** @var null|File */
    private $__curr_input_file = null;
    private $__curr_input_is_empty = true;
    /** @var JsonExport */
    private $__JsonExporter;
    private $__raw_mode = true;

    public $non_restrictive_export = true;

    public function __construct()
    {
        $this->__JsonExporter = new JsonExport();
    }

    private static function __count_atributes($data)
    {
        $attributes_count = count($data['Attribute']);
        foreach ($data['Object'] as $_object) {
           $attributes_count += count($_object['Attribute']);
        }
        return $attributes_count;
    }

    public function header($options = array())
    {
        $this->__initialize_misp_file($options);

        $this->__yara_file_gen = FileAccessTool::createTempFile();
        $this->__yara_file_asis = FileAccessTool::createTempFile();

        if ($options['returnFormat'] === 'yara-json') {
            $this->__raw_mode = false;
        }
        return '';
    }

    /**
     * @throws Exception
     */
    private function __initialize_misp_file($options)
    {
        $this->__curr_input_file = new File(FileAccessTool::createTempFile());
        $header = $this->__JsonExporter->header($options);
        $this->__curr_input_file->append($header);
        $this->__curr_input_is_empty = true;
    }

    public function handler($data, $options = array())
    {
        // convert attribute(s) to json and write them to input queue file
        if ($options['scope'] === 'Attribute') {
            $attr_count = 1;
        } else if ($options['scope'] === 'Event') {
            $attr_count = $this->__count_atributes($data);
        }
        if (!empty($data)) {
            if (!$this->__curr_input_is_empty) {
                $this->separator(); // calling separator since returning '' will prevent it
            }
            $jsonData = $this->__JsonExporter->handler($data, $options);
            if ($jsonData instanceof Generator) {
                foreach ($jsonData as $part) {
                    $this->__curr_input_file->append($part);
                }
            } else {
                $this->__curr_input_file->append($jsonData);
            }
            $this->__curr_input_is_empty = false;
        }
        $this->__n_attributes += $attr_count;
        // if the file exceeds the max_attributes, process it, delete it and reset the counter
        if ($this->__n_attributes >= $this->__MAX_n_attributes) {
            $this->__process_file($options);
            $this->__initialize_misp_file($options);
        }
        return '';
    }

    /**
     * @param array $options
     * @return TmpFileTool
     * @throws Exception
     */
    public function footer($options = array())
    {
        if (!$this->__curr_input_is_empty) {
            $this->__process_file($options);
        }

        $output = new TmpFileTool();

        if ($this->__raw_mode)  {
            $output->write('// ===================================== GENERATED ===================================='. PHP_EOL);
            $output->writeFromFile($this->__yara_file_gen);
            $output->write(PHP_EOL . '// =====================================   AS-IS  ===================================='. PHP_EOL);
            $output->writeFromFile($this->__yara_file_asis);
        } else {
            $output->write('{"generated":[');
            $output->writeFromFile($this->__yara_file_gen);
            $output->write('],"as-is":[');
            $output->writeFromFile($this->__yara_file_asis);
            $output->write(']}');
        }

        FileAccessTool::deleteFile($this->__yara_file_gen);
        FileAccessTool::deleteFile($this->__yara_file_asis);

        return $output;
    }

    public function separator()
    {
        if (!$this->__curr_input_is_empty) {
            $this->__curr_input_file->append(',');
        }
        return '';
    }

    private function __process_file($options)
    {
        $footer = $this->__JsonExporter->footer($options);
        $this->__curr_input_file->append($footer);
        $this->__curr_input_file->close();

        $command = [
            ProcessTool::pythonBin(),
            $this->__script_path,
            '--input', $this->__curr_input_file->path,
            '--out-generated', $this->__yara_file_gen,
            '--out-asis', $this->__yara_file_asis,
        ];
        if ($this->__raw_mode) {
            $command[] = '--raw';
        }

        ProcessTool::execute($command, null, true);

        $this->__curr_input_file->delete();
        $this->__n_attributes = 0;
    }
}
