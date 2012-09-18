<?php

class HidsSha1ExportComponent extends Component {

	public $rules = array();

	public function explain() {
		// unshift add in reverse order
		array_unshift($this->rules, '# ');
		array_unshift($this->rules, '# Keep in mind SHA-1 still has a theoretical collision possibility');
		array_unshift($this->rules, '# These HIDS export contains SHA-1 checksums.');
	}

	public function suricataRules($items) {
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
