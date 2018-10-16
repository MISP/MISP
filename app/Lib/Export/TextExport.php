<?php

class TextExport
{
	public $additional_params = array(
		'flatten' => 1
	);

	public function handler($data, $options = array())
	{
		if ($options['scope'] === 'Attribute') {
			return $data['Attribute']['value'];
		}
		if ($options['scope'] === 'Event') {
			$result = array();
			foreach ($data['Attribute'] as $attribute) {
				$result[] = $attribute['value'];
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
