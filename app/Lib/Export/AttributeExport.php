<?php

class AttributeExport
{

    public function handler($attribute, $options = array())
    {
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
        return ',' . PHP_EOL;
    }

}
