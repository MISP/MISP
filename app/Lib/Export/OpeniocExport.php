<?php

class OpeniocExport
{
    const MAPPING = array(
        'composite' => array(
            'regkey|value' => array(array('Network', 'RegistryItem/KeyPath', 'string'), array('Network', 'RegistryItem/Value', 'string')),
            'filename|md5' => array(array('FileItem', 'FileItem/FileName', 'string'), array('FileItem', 'FileItem/Md5sum', 'md5')),
            'filename|sha1' => array(array('FileItem', 'FileItem/FileName', 'string'), array('FileItem', 'FileItem/Sha1sum', 'sha1')),
            'filename|sha256' => array(array('FileItem', 'FileItem/FileName', 'string'), array('FileItem', 'FileItem/Sha256sum', 'sha256')),
            'malware-sample' => array(array('FileItem', 'FileItem/FileName', 'string'), array('FileItem', 'FileItem/Md5sum', 'md5')),
            'domain|ip' => array(array('Network', 'Network/DNS', 'string'), array('PortItem', 'PortItem/remoteIP', 'IP')),
        ),
        'simple' => array(
            'md5' => array('FileItem', 'FileItem/Md5sum', 'md5'),
            'sha1' => array('FileItem', 'FileItem/Sha1sum', 'sha1'),
            'sha256' => array('FileItem', 'FileItem/Sha256sum', 'sha256'),
            'filename' => array('FileItem', 'FileItem/FileName', 'string'),
            'ip-src' => array('PortItem', 'PortItem/remoteIP', 'IP'),
            'ip-dst' => array('RouteEntryItem', 'RouteEntryItem/Destination', 'IP'),
            'hostname' => array('RouteEntryItem', 'RouteEntryItem/Destination', 'string'),
            'email' => array('Email', 'Email/From', 'string'),
            'email-src' => array('Email', 'Email/From', 'string'),
            'email-dst' => array('Email', 'Email/To', 'string'),
            'email-subject' => array('Email', 'Email/Subject', 'string'),
            'email-attachment' => array('Email', 'Email/Attachment/Name', 'string'),
            'domain' => array('Network', 'Network/DNS', 'string'),
            'url' => array('UrlHistoryItem', 'UrlHistoryItem/URL', 'string'),
            'user-agent' => array('Network', 'Network/UserAgent', 'string'),
            'regkey' => array('Network', 'RegistryItem/KeyPath', 'string'),
            'snort' => array('Snort', 'Snort/Snort', 'string'),
            'attachment' => array('FileItem', 'FileItem/FileName', 'string'),
            'link' => array('URL', 'UrlHistoryItem/URL', 'md5')
        )
    );

	public $additional_params = array(
		'flatten' => 1
	);

    private function frameComposite($attribute)
    {
        $mapping = self::MAPPING['composite'][$attribute['type']];
        $temp = '';
        $values = explode('|', $attribute['value']);
        $temp .= '     <Indicator operator="AND" id="' . h($attribute['uuid']) . '">' . PHP_EOL;
        $temp .= $this->frameIndicator($mapping[0], $attribute['uuid'], $values[0], true);
        $temp .= $this->frameIndicator($mapping[1], $attribute['uuid'], $values[1], true);
        $temp .= '      </Indicator>' . PHP_EOL;
        return $temp;
    }

    private function frameIndicator($mapping, $uuid, $value, $extraIndent = false)
    {
        $temp = '';
        $padding = $extraIndent ? 8 : 6;
        $temp .= str_repeat(' ', $padding) . '<IndicatorItem id="' . h($uuid) . '" condition="is">' . PHP_EOL;
        $temp .= str_repeat(' ', ($padding + 2)) . '<Context document="' . $mapping[0] . '" search="' . $mapping[1] . '" type="mir" />' . PHP_EOL;
        $temp .= str_repeat(' ', ($padding + 2)) . '<Content type="' . $mapping[2] . '">' . h($value) . '</Content>' . PHP_EOL;
        $temp .= str_repeat(' ', $padding) . '</IndicatorItem>' . PHP_EOL;
        return $temp;
    }

    // Simple check for valid categories and types for IOC generation
    private function checkValidTypeForIOC($attribute)
    {
        // categories that should be included
        $category = array('Payload delivery', 'Artifacts dropped', 'Payload installation', 'Persistence mechanism', 'Network activity');
        return in_array($attribute['category'], $category, true);
    }

	private function attributeHandler($attribute, $options = array())
    {
		if (isset($attribute['Attribute'])) {
			$attribute = $attribute['Attribute'];
		}
		// Hop over attributes that don't have the to ids flag turned on and check whether the attribute is sent for IOC export based on category/type
		if (!$this->checkValidTypeForIOC($attribute) || $attribute['to_ids'] == 0) {
			return false;
		}
		if ($attribute['type'] === 'malware-sample') {
			$attribute['type'] = 'filename|md5';
		}
		if (strpos($attribute['type'], '|')) {
			if (isset(self::MAPPING['composite'][$attribute['type']])) {
				return $this->frameComposite($attribute);
			}
		} else {
			if (isset(self::MAPPING['simple'][$attribute['type']])) {
				return $this->frameIndicator(self::MAPPING['simple'][$attribute['type']], $attribute['uuid'], $attribute['value'], false);
			}
		}
		return false;
	}

    public function handler($data, $options = array())
    {
		if ($options['scope'] === 'Attribute') {
			return $this->attributeHandler($data, $options);
		} else if ($options['scope'] === 'Event') {
			$result = '';
			if (!empty($data['Attribute'])) {
				foreach ($data['Attribute'] as $attribute) {
					$temp = $this->attributeHandler($attribute, $options);
					if (!empty($temp)) {
						$result .= $temp;
					}
				}
			}
			return $result;
		}
    }

    public function header($options = array())
    {
		$user = $options['user'];
		$temp = '';
		// We will start adding all the components that will be in the xml file here
		$date = date("Y-m-d\Th:i:s");
		$temp .= '<?xml version="1.0" encoding="utf-8"?>' . PHP_EOL;
		$temp .= '<ioc xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" id="' . CakeText::uuid() . '" last-modified="' . $date . '" xmlns="http://schemas.mandiant.com/2010/ioc">' . PHP_EOL;
		$temp .= '  <short_description>Filtered indicator list</short_description>' . PHP_EOL;
		$temp .= '  <description>Filtered indicator list</description>' . PHP_EOL;
		$temp .= '  <keywords />' . PHP_EOL;
		$temp .= '  <authored_by>' . h($user['Organisation']['name']) . '</authored_by>' . PHP_EOL;
		$temp .= '  <authored_date>' . $date . '</authored_date>' . PHP_EOL;
		$temp .= '  <links />' . PHP_EOL;
		$temp .= '  <definition>' . PHP_EOL;
		$temp .= '    <Indicator operator="OR" id="' . CakeText::uuid() . '">' . PHP_EOL;
		return $temp;
    }

    public function footer()
    {
		$temp = '';
		$temp .= '    </Indicator>' . PHP_EOL;
		$temp .= '  </definition>' . PHP_EOL;
		$temp .= '</ioc>' . PHP_EOL;
		return $temp;
    }

    public function separator()
    {
        return '';
    }
}
