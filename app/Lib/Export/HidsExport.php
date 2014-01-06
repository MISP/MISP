<?php

class HidsExport {

	public $rules = array();

	public function explain($type) {
		// unshift add in reverse order
		array_unshift($this->rules, '# ');
		if ($type === 'MD5') {
			array_unshift($this->rules, '# Keep in mind MD5 is not collision resistant');
		} else if ($type === 'SHA1') {
			array_unshift($this->rules, '# Keep in mind SHA-1 still has a theoretical collision possibility');
		}		
		array_unshift($this->rules, '# These HIDS export contains ' . $type . ' checksums.');
	}

	public function export($items, $type = 'MD5') {
		$itemsDone = array();
		foreach ($items as &$item) {

			# md5
			$ruleFormat = '%s';

			$attribute = &$item['Attribute'];

			switch ($attribute['type']) {
				case 'md5':
				case 'sha1':
					if (!in_array ($attribute['value1'], $itemsDone)) {
						$this->checksumRule($ruleFormat, $attribute);
						$itemsDone[] = $attribute['value1'];
					}
					break;
				case 'filename|md5':
				case 'malware-sample':
				case 'filename|sha1':
					if (!in_array ($attribute['value2'], $itemsDone)) {
						$this->partRule($ruleFormat, $attribute);
						$itemsDone[] = $attribute['value2'];
					}
					break;
				default:
					break;

			}

		}

		sort($this->rules);
		$this->explain($type);

		return $this->rules;
	}

	public function checksumRule($ruleFormat, $attribute) {
		$this->rules[] = sprintf($ruleFormat,
				$attribute['value1']			// md5
				);
	}

	public function partRule($ruleFormat, $attribute) {
		$this->rules[] = sprintf($ruleFormat,
				$attribute['value2']			// md5
				);
	}

}
