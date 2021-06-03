<?php
App::uses('JsonExport', 'Export');
App::uses('AppModel', 'Model');

class YaraExport
{
    private $__script_path = APP . 'files/scripts/yara/yaraexport.py';
    private $__tmp_dir = APP . 'tmp/yara/';
    private $__end_of_cmd = ' 2>>' . APP . 'tmp/logs/yara_export.log';
    private $__n_attributes = 0;
    private $__MAX_n_attributes = 15000;
    private $__yara_file_gen = null;
    private $__yara_file_asis = null;
    /** @var null|File */
    private $__curr_input_file = null;
    private $__scope = false;
    private $__curr_input_is_empty = true;
    private $__JsonExporter = false;
    private $__raw_mode = true;

    public $non_restrictive_export = true;

    private static function __count_atributes($data)
    {
      $attributes_count = count($data['Attribute']);
      // foreach ($data['Object'] as $_object) {
      //     $attributes_count += count($_object['Attribute']);
      // }
    }

    public function header($options = array())
    {
        if($this->__JsonExporter === false){
            $this->__JsonExporter = new JsonExport();
        }
        $this->__initialize_yara_file();
        $this->__initialize_misp_file($options);
        if($options['returnFormat'] === 'yara-json'){
            $this->__raw_mode = false;
        }
        return '';
    }

    private function __initialize_yara_file()
    {
        $yaraFileName = $this->generateRandomFileName();
        $this->__yara_file_gen = new File($this->__tmp_dir . $yaraFileName . '_generated', true, 0644);
        $this->__yara_file_asis = new File($this->__tmp_dir . $yaraFileName . '_asis', true, 0644);
        $this->__yara_file_gen->close();
        $this->__yara_file_asis->close();
    }

    private function __initialize_misp_file($options)
    {
        $mispFileName = $this->generateRandomFileName();
        $this->__curr_input_file = new File($this->__tmp_dir . $mispFileName, true, 0644);
        $header = $this->__JsonExporter->header($options);
        $this->__curr_input_file->append($header);
        $this->__curr_input_is_empty = true;
    }

    public function handler($data, $options = array())
    {
        // convert attribute(s) to json and write them to input queue file
        if ($options['scope'] === 'Attribute') {
            $attr_count = 1;
        } else if($options['scope'] === 'Event') {
            $attr_count = YaraExport::__count_atributes($data);
        }
        if(!empty($data)){
            if(!$this->__curr_input_is_empty){
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
        if ($this->__n_attributes >= $this->__MAX_n_attributes){
            $this->__process_file($options);
            $this->__initialize_misp_file($options);
        }
        return '';
    }

    public function footer($options = array())
    {
        if(!($this->__curr_input_is_empty)){
            $this->__process_file($options);
        }
        $file = new File($this->__yara_file_gen->path);
        $data_gen = $file->read(true, 'r');
        $file->close();
        $file->delete();
        $file = new File($this->__yara_file_asis->path);
        $data_asis = $file->read(true, 'r');
        $file->close();
        $file->delete();
        if($this->__raw_mode){
            $output =
              '// ===================================== GENERATED ===================================='. PHP_EOL .
              $data_gen . PHP_EOL .
              '// =====================================   AS-IS  ===================================='. PHP_EOL .
              $data_asis;
        }else{
            $output =  '{"generated":['. $data_gen .'],'.
                    '"as-is":[' . $data_asis . ']}';
        }
        return $output;
    }

    public function separator()
    {
        if(!$this->__curr_input_is_empty){
            $this->__curr_input_file->append(',');
        }
        return '';
    }

    private function __process_file($options)
    {
        $footer = $this->__JsonExporter->footer($options);
        $this->__curr_input_file->append($footer);
        $pythonScript = $this->__script_path;
        $in = $this->__curr_input_file->path;
        $out1 = $this->__yara_file_gen->path;
        $out2 = $this->__yara_file_asis->path;
        $logging = $this->__end_of_cmd;
        $raw_flag = $this->__raw_mode ? '--raw' : '';
        $my_server = ClassRegistry::init('Server');
        $result = shell_exec($my_server->getPythonVersion() . " $pythonScript --input $in --out-generated $out1 --out-asis $out2 $raw_flag $logging");
        $this->__curr_input_file->close();
        $this->__curr_input_file->delete();
        $this->__n_attributes = 0;
    }

    public function generateRandomFileName()
    {
        return (new RandomTool())->random_str(false, 12);
    }
}
