<?php

class IOCExportComponent extends Component {

	private $final = array();

	public function buildAll($user, $event) {
		$this->__buildTop($event);
		foreach ($event['Attribute'] as &$attribute) {
			$this->__buildAttribute($attribute);
		}
		$this->__buildBottom();
		return $this->final;
	}

	// Builds the top with the event information
	private function __buildTop($event) {
		// We will start adding all the components that will be in the xml file here
		$this->final[] = '<?xml version="1.0" encoding="utf-8"?>';
		$this->final[] = '<ioc xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" id="' . $event['Event']['uuid'] . '" last-modified="' . $event['Event']['date'] . 'T00:00:00" xmlns="http://schemas.mandiant.com/2010/ioc">';
		$this->final[] = '  <short_description>Event #' . h($event['Event']['id']) . '</short_description>';
		$this->final[] = '  <description>' . h($event['Event']['info']) . '</description>';
		$this->final[] = '  <keywords />';
		$this->final[] = '  <authored_by>' . h($event['Orgc']['name']) . '</authored_by>';
		$this->final[] = '  <authored_date>' . h($event['Event']['date']) . 'T00:00:00</authored_date>';
		$this->final[] = '  <links />';
		$this->final[] = '  <definition>';
		// for now, since we don't have any logical links between attributes, we'll OR all of them
		$this->final[] = '    <Indicator operator="OR" id="' . h($event['Event']['uuid']) . '">';
	}

	public $mapping = array(
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
	
	private function __frameComposite($attribute) {
		$types = explode('|', $attribute['type']);
		$values = explode('|', $attribute['value']);
		$this->final[] = '     <Indicator operator="AND" id="' . h($attribute['uuid']) . '">';
		$this->__frameIndicator($this->mapping['composite'][$attribute['type']][0], $attribute['uuid'], $values[0], true);
		$this->__frameIndicator($this->mapping['composite'][$attribute['type']][1], $attribute['uuid'], $values[1], true);
		$this->final[] = '      </Indicator>';
	}
	
	private function __frameIndicator($mapping, $uuid, $value, $extraIndent = false) {
		$indent = "      ";
		$padding = 6;
		if ($extraIndent) {
			$padding = 8;
		}
		$this->final[] = str_repeat(' ', $padding) . '<IndicatorItem id="' . h($uuid) . '" condition="is">';
		$this->final[] = str_repeat(' ', ($padding + 2)) . '<Context document="' . $mapping[0] . '" search="' . $mapping[1] . '" type="mir" />';
		$this->final[] = str_repeat(' ', ($padding + 2)) . '<Content type="' . $mapping[2] . '">' . h($value) . '</Content>';
		$this->final[] = str_repeat(' ', $padding) . '</IndicatorItem>';
	}
	
	// This method will turn each eligible attribute into an indicator
	private function __buildAttribute($attribute) {
		// Hop over attributes that don't have the to ids flag turned on and check whether the attribute is sent for IOC export based on category/type
		if (!$this->__checkValidTypeForIOC($attribute) || $attribute['to_ids'] == 0) return;
		if ($attribute['type'] == 'malware-sample') $attribute['type'] = 'filename|md5';
		if (strpos($attribute['type'], '|')) {
			if ($this->mapping['composite'][$attribute['type']]) {
				$this->__frameComposite($attribute);
			}
		} else {
			if (isset($this->mapping['simple'][$attribute['type']])) {
				$this->__frameIndicator($this->mapping['simple'][$attribute['type']], $attribute['value'], false);
			}
		}		
	}

	// Just closing some tags at the bottom of the .ioc file
	private function __buildBottom() {
		$this->final[] = '    </Indicator>';
		$this->final[] = '  </definition>';
		$this->final[] = '</ioc>';
	}

	// Simple check for valid categories and types for IOC generation
	private function __checkValidTypeForIOC($attribute) {
		// categories that should be included
		$Category = array('Payload delivery', 'Artifacts dropped', 'Payload installation', 'Persistence mechanism', 'Network activity');
		if (!in_array($attribute['category'], $Category)) return false;
		return true;
	}
}
