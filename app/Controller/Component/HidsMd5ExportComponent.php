<?php

class HidsMd5ExportComponent extends Component {

	public $rules = array();

	public function explain() {
		// unshift add in reverse order
		array_unshift($this->rules, '# ');
		array_unshift($this->rules, '# Keep in mind MD5 is not collision resistant');
		array_unshift($this->rules, '# These HIDS export contains MD5 checksums.');
	}

	public function suricataRules($items) {
		$itemsDone = array();
		foreach ($items as &$item) {

			# md5
			$rule_format = '%s';

			$attribute = &$item['Attribute'];

			switch ($attribute['type']) {
				case 'md5':
					if (!in_array ($attribute['value1'], $itemsDone)) {
						$this->checksumRule($rule_format, $attribute);
						$itemsDone[] = $attribute['value1'];
					}
					break;
				case 'filename|md5':
				case 'malware-sample':
					if (!in_array ($attribute['value2'], $itemsDone)) {
						$this->partRule($rule_format, $attribute);
						$itemsDone[] = $attribute['value2'];
					}
					break;
				default:
					break;

			}

		}

		sort($this->rules);
		$this->explain();

		return $this->rules;
	}

	public function checksumRule($rule_format, $attribute) {
		$this->rules[] = sprintf($rule_format,
				$attribute['value1']			// md5
				);
	}

	public function partRule($rule_format, $attribute) {
		$this->rules[] = sprintf($rule_format,
				$attribute['value2']			// md5
				);
	}

}
