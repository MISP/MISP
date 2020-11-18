<?php

class JsonExport
{
	private $__converter = false;
	public $non_restrictive_export = true;

    /**
     * @param $data
     * @param array $options
     * @return false|Generator|string
     */
    public function handler($data, $options = array())
    {
		if ($options['scope'] === 'Attribute') {
			return $this->__attributeHandler($data, $options);
		} else if($options['scope'] === 'Event') {
			return $this->__eventHandler($data, $options);
        } else if($options['scope'] === 'Object') {
            return $this->__objectHandler($data, $options);
		} else if($options['scope'] === 'Sighting') {
			return $this->__sightingsHandler($data, $options);
		} else if($options['scope'] === 'GalaxyCluster') {
			return $this->__galaxyClusterHandler($data, $options);
		}
    }

    /**
     * @param array $event
     * @param array $options
     * @return Generator
     */
	private function __eventHandler($event, $options = array())
    {
		if ($this->__converter === false) {
			App::uses('JSONConverterTool', 'Tools');
			$this->__converter = new JSONConverterTool();
		}
		return $this->__converter->streamConvert($event);
	}

    private function __objectHandler($object, $options = array()) {
        if ($this->__converter === false) {
            App::uses('JSONConverterTool', 'Tools');
            $this->__converter = new JSONConverterTool();
        }
        return json_encode($this->__converter->convertObject($object, false, true));
    }

	private function __attributeHandler($attribute, $options = array())
	{
		$attribute = array_merge($attribute['Attribute'], $attribute);
		unset($attribute['Attribute']);
		if (isset($attribute['Object']) && empty($attribute['Object']['id'])) {
			unset($attribute['Object']);
		}
		$tagTypes = array('AttributeTag', 'EventTag');
		foreach($tagTypes as $tagType) {
			if (isset($attribute[$tagType])) {
				foreach ($attribute[$tagType] as $tk => $tag) {
					if ($tagType === 'EventTag') {
						$attribute[$tagType][$tk]['Tag']['inherited'] = 1;
					}
					$attribute['Tag'][] = $attribute[$tagType][$tk]['Tag'];
				}
				unset($attribute[$tagType]);
			}
		}
		unset($attribute['value1']);
		unset($attribute['value2']);
		return json_encode($attribute);
	}

    private function __sightingsHandler($sighting, $options = array())
    {
        return json_encode($sighting);
    }
    private function __galaxyClusterHandler($cluster, $options = array())
    {
        return json_encode($cluster);
    }

    public function header($options = array())
    {
		if ($options['scope'] === 'Attribute') {
			return '{"response": {"Attribute": [';
		} else {
			return '{"response": [';
		}
    }

    public function footer($options = array())
    {
		if ($options['scope'] === 'Attribute') {
			return ']}}' . PHP_EOL;
		} else {
			return ']}' . PHP_EOL;
		}
    }

    public function separator()
    {
        return ',';
    }
}
