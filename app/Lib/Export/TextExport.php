<?php

class TextExport
{
	public $additional_params = array(
		'flatten' => 1
	);

    private $__resultSet = [];

	public function handler($data, $options = array())
	{
		if ($options['scope'] === 'Attribute') {
			$this->__resultSet[$data['Attribute']['value']] = true;
		}
		if ($options['scope'] === 'Event') {
			$result = array();
			foreach ($data['Attribute'] as $attribute) {
				$this->__resultSet[$attribute['value']] = true;
			}
		}
		return '';
	}

	public function header($options = array())
	{
		return '';
	}

	public function footer()
	{
        return implode("\n", array_keys($this->__resultSet)) . "\n";
	}

	public function separator()
	{
		return '';
	}
}
