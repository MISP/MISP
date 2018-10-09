<?php

class CacheExport
{
	public $additional_params = array(
		'flatten' => 1
	);

	public $non_restrictive_export = true;

	public function handler($data, $options = array())
	{
		$hash_type = empty($options['filters']['hash_type']) ? 'md5' : $options['filters']['hash_type'];
		if (!in_array($hash_type, hash_algos())) {
			throw new MethodNotAllowedException('Invalid hashing algo');
		}
		if ($options['scope'] === 'Attribute') {
			return hash($hash_type, $data['Attribute']['value']);
		}
		if ($options['scope'] === 'Event') {
			$result = array();
			foreach ($data['Attribute'] as $attribute) {
				$result[] = hash($hash_type, $data['Attribute']['value']);
			}
			return implode($this->separator(), $result);
		}
		return '';
	}

	public function header($options = array())
	{
		return '';
	}

	public function footer()
	{
		return "\n";
	}

	public function separator()
	{
		return "\n";
	}
}
