<?php

class JsonExport
{
    public function handler($data, $options = array())
    {
		if ($options['scope'] === 'Attribute') {
			return $this->__attributeHandler($data, $options);
		} else {
			return $this->__eventHandler($data, $options);
		}
    }

	private function __attributeHandler($attribute, $options = array())
	{
		$attribute = array_merge($attribute['Attribute'], $attribute);
		unset($attribute['Attribute']);
		if (isset($attribute['Object']) && empty($attribute['Object']['id'])) {
			unset($attribute['Object']);
		}
		if (isset($attribute['AttributeTag'])) {
			$attributeTags = array();
			foreach ($attribute['AttributeTag'] as $tk => $tag) {
				$attribute['Tag'][$tk] = $attribute['AttributeTag'][$tk]['Tag'];
			}
			unset($attribute['AttributeTag']);
			unset($attribute['value1']);
			unset($attribute['value2']);
		}
		return json_encode($attribute);
	}

    public function header($options = array())
    {
		return '{"response": {"Attribute": [';
    }

    public function footer()
    {
		return ']}}' . PHP_EOL;
    }

    public function separator()
    {
        return ',';
    }

}
