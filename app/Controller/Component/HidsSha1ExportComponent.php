<?php

class HidsSha1ExportComponent extends Component {

    public $rules = array();

    function explain() {
        $this->rules[] = '# These HIDS export contains SHA-1 checksums.';
        $this->rules[] = '# Keep in mind SHA-1 still has a theoretical collision possibility';
        $this->rules[] = '# ';
    }

    function suricataRules($items) {

        $this->explain();

	$itemsDone = array();

        foreach ($items as &$item) {


            # sha-1
            $rule_format = '%s';

            $attribute = &$item['Attribute'];

            switch ($attribute['type']) {
                case 'sha1':
                    if (!in_array ($attribute['value1'], $itemsDone)) {
                        $this->checksumRule($rule_format, $attribute);
                        $itemsDone[] = $attribute['value1'];
                    }
                    break;
            	case 'filename|sha1':
                    if (!in_array ($attribute['value2'], $itemsDone)) {
                        $this->partRule($rule_format, $attribute);
                        $itemsDone[] = $attribute['value2'];
                    }
                    break;
                default:
                    break;


            }

        }



		return $this->rules;


    }

    function checksumRule($rule_format, $attribute) {
        $this->rules[] = sprintf($rule_format,
                $attribute['value1']            // md5
                );

    }

    function partRule($rule_format, $attribute) {
        $this->rules[] = sprintf($rule_format,
                $attribute['value2']            // md5
                );
    }

}
