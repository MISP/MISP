<?php

class TextExport
{
	public function handler($data, $options = array())
	{
		if ($options['scope'] === 'Attribute') {
			return $data['Attribute']['value'];
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
