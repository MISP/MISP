<?php

class IOCImportComponent extends Component {

	// predefined attribute pairs that should be saved together - these are the exceptions to AND operators that will not be omitted
	// The format is: attribute1, attribute2, new type, category, behaviour.
	// Behaviour can be one of the following: 'first', 'second', 'both'  -> this explains what the attribute that is to be created should carry as a value
	// first means that the value will be equal to the first attribute, second means that it will equal that of the second. Both will add both separated by '|'
	public $attributePairs = array(
			array('filename', 'md5', 'filename|md5', 'Payload installation', 'both'),
			array('filename', 'sha1', 'filename|sha1', 'Payload installation', 'both'),
			array('regkey', 'tempRegValue', 'regkey|value', 'Persistence mechanism', 'both'),
			array('filename', 'tempCertificateSubject', 'filename', 'Payload installation', 'first'),
		);

	public function readXML($data, $id) {
		//ClassRegistry::init('Attribute');
		$event = array();
		$attributes = array();
		$fails = array();

		// import XML class
		App::uses('Xml', 'Utility');

		// now parse it
		$xmlArray = json_decode(json_encode((array) simplexml_load_string($data)), 1);
		$temp = $xmlArray;
		$xmlArray = array();
		$xmlArray['ioc'] = $temp;
		// add an attribute that holds the full description of the imported report.
		$attributes[] = array(
				'event_id' => $id,
				'value' => $xmlArray['ioc']['description'],
				'to_ids' => false,
				'uuid' => String::uuid(),
				'category' => 'Other',
				'type' => 'comment'
				);

		// set the event info based on the import.
		$event['info'] = $xmlArray['ioc']['short_description'] . PHP_EOL .'By ' . $xmlArray['ioc']['authored_by'];
		$event['date'] = $xmlArray['ioc']['authored_date'];
		$event['uuid'] = $xmlArray['ioc']['@attributes']['id'];
		foreach ($xmlArray['ioc']['definition'] as $current) {
			if($current['@attributes']['operator'] == 'OR' && isset($current['IndicatorItem'])) {
				foreach ($current['IndicatorItem'] as $ii) {
					$temp = $this->__analyseIndicator($ii, $id);
					$attributes[] = $temp;
				}
			} else {
				$fails[] = $current;
			}
		}

		// Try to see if any of the AND-ed indicators can be salvaged and converted instead of being discarded
		foreach ($xmlArray['ioc']['definition'] as $current) {
			foreach ($current['Indicator'] as $key => $value) {
				// During the xml->array conversion, if there is only a single indicator, it will be build directly as a child of definition,
				// instead of the first element of an array. Here we move the IndicatorItem one level down
				if ($key === 'IndicatorItem') {
					$key = 0;
					$value = array ('IndicatorItem' => $value);
				}
				if (isset($value['IndicatorItem']) && count($value['IndicatorItem']) == 2) {
					$att1 = $this->__analyseIndicator($value['IndicatorItem'][0], $id);
					$att2 = $this->__analyseIndicator($value['IndicatorItem'][1], $id);
					$attempt = $this->__convertToCompositeAttribute($att1, $att2, $current['@attributes']['id']);
					if ($attempt) {
						$attributes[] = $attempt;
					}
				} else {
						$fails[] = $value;
				}
				// If it is the only indicator, jump straight to the IndicatorItem
			}
		}

		// remove all the temporary attribute types used for the pairing and turn them all into "other"
		foreach ($attributes as &$att) {
			if (substr($att['type'], 0, 3) === 'temp') {
				$temp = $this->__convertToOther($temp);
			}
		}

		// Add the attributes to the event that will be returned
		$event['Attribute'] = $attributes;

		// Add the failed indicators to the event that will be returned
		if (!empty($fails)) {
			$event['Fails'] = $this->__fetchFailedUuids($fails);
		}
		// return the event with the attributes and failed indicators
		return $event;
	}

	// dissect the indicator and convert it into an attribute
	private function __analyseIndicator($ii, $id) {
		$attribute = array();
		$attribute['event_id'] = $id;
		$attribute['uuid'] = $ii['@attributes']['id'];
		$attribute['value'] = $ii['Content'];
		$attribute['to_ids'] = false;
		$attribute['search'] = $ii['Context']['@attributes']['search'];
		$temp = $this->__checkType($ii['Context']['@attributes']['search']);
		if (!$temp) return false;
		$attribute['category'] = $temp[0];
		$attribute['type'] = $temp[1];
		// If we couldn't figure out the category / type and got Other/other, append the search term in the value
		if ($temp[0] == 'Other' && $temp[1] == 'other') {
			$attribute['value'] = $attribute['search'] . ': ' . $attribute['value'];
		}
		return $attribute;
	}

	// used to save the value of attributes of type other (attributes that could not be mapped) and convert temporary attributes to type other.
	private function __convertToOther(&$attribute) {
		$attribute['category'] = 'Other';
		$attribute['type'] = 'other';
		$attribute['value'] = $attribute['search'] . ': ' . $attribute['value'];
	}

	// Attempt to convert the two attributes retrieved from an AND indicator into a single attribute, if they are eligible to be converted. If not, add it to the array of failures.
	private function __convertToCompositeAttribute($att1, $att2, $uuid) {
		// check if the current attribute is one of the known pairs saved in the array $attributePairs
		foreach ($this->attributePairs as $pair) {
			// if attribute 1's type = the first type of the pair and attribute 2's type is the type of the second attribute of the pair, return a new joint attribute with the new type-name (usually type1|type2) and its predefined category
			if($att1['type'] == $pair[0] && $att2['type'] == $pair[1]) {
				if ($pair[4] == 'both') $value = $att1['value'] . '|' . $att2['value'];
				// switch to see which value to keep and which to get rid of
				switch ($pair[4]) {
					case 'first':
						$value = $att1['value'];
						break;
					case 'second':
						$value = $att2['value'];
						break;
					default:
						$value = $att1['value'] . '|' . $att2['value'];
				}
				return array('type' => $pair[2], 'value' => $value, 'uuid' => $uuid, 'category' => $pair[3], 'event_id' => $att1['event_id'], 'to_ids' => false);
			}
			// Try the same thing above with the attributes reversed
			if ($att2['type'] == $pair[0] && $att1['type'] == $pair[1]) {
				// switch to see which value to keep and which to get rid of
				switch ($pair[4]) {
					case 'first':
						$value = $att2['value'];
						break;
					case 'second':
						$value = $att1['value'];
						break;
					default:
						$value = $att2['value'] . '|' . $att1['value'];
				}
				return array('type' => $pair[2], 'value' => $value, 'uuid' => $uuid, 'category' => $pair[3], 'event_id' => $att1['event_id'], 'to_ids' => false);
			}
		}
		// If no match found, return false, it's not a valid composite attribute for MISP
		return false;
	}

	private function __checkType($type) {
		// Here we have to figure out how to best map the indicator to an attribute. This is an initial mapping, needs lots of tweaks still
		// Keep in mind: names starting with "temp" will only be used for composite types, then changed to Other -> other.
		switch ($type) {
			case 'FileItem/FileName':
			case 'DriverItem/DriverName':
			case 'FileItem/FullPath':
				return array('Payload installation', 'filename');
				break;
			case 'FileItem/Md5sum':
				return array('Payload installation', 'md5');
				break;
			case 'TaskItem/sha1sum':
				return array('Payload installation', 'sha1');
				break;
			case 'PortItem/remoteIP':
				return array('Network activity', 'ip-src');
				break;
			case 'RouteEntryItem/Gateway':
			case 'RouteEntryItem/Destination':
				return array('Network activity', 'ip-dst');
				break;
			case 'SystemInfoItem/domain':
				return array('Network activity', 'domain');
				break;
			case 'Email/To':
				return array('Payload delivery', 'email-dst');
				break;
			case 'Email/From':
				return array('Payload delivery', 'email-src');
				break;
			case 'Email/Subject':
				return array('Payload delivery', 'email-subject');
				break;
			case 'Email/Attachment/Na':
				return array('Payload delivery', 'email-attachment');
				break;
			case 'UrlHistoryItem/URL':
			case 'UrlHistoryItem/VisitFrom':
			case 'FileDownloadHistoryItem/SourceURL':
			case 'FormHistoryItem/FormSubmitURL':
				return array('Network activity', 'url');
				break;
			case 'Network/UserAgent':
				return array('Network activity', 'user-agent');
				break;
			case 'RegistryItem/KeyPath':
			case 'RegistryItem/Modified':
			case 'RegistryItem/Path':
				return array('Persistence mechanism', 'regkey');
				break;
			case 'Snort/Snort':
				return array('Network activity', 'snort');
				break;
			case 'TaskItem/Comment':
				return array('Other', 'comment');
				break;
			case 'CookieHistoryItem/HostName':
			case 'FormHistoryItem/HostName':
			case 'SystemInfoItem/hostname':
			case 'UrlHistoryItem/HostName':
				return array('Network Activity', 'hostname');
				break;
			case 'RegistryItem/Text':
				return array('Persistence mechanism', 'tempRegValue');
				break;
			// We don't keep the following, they are often used with AND and a filename. We'll only keep the filename in those cases.
			case 'FileItem/PEInfo/DigitalSignature/CertificateSubject':
			case 'FileItem/PEInfo/DigitalSignature/SignatureExists':
				return array('Payload delivery', 'tempCertificateSubject');
				break;
		}
		return array('Other', 'other');
	}

	private function __fetchFailedUuids($fails) {
		$failedAttributes = array();
		$this->__saveFailedUuids($fails, $failedAttributes);
		return $failedAttributes;
	}

	// Recursive search for all of the indicators that could not be entered - if an item has an id and context - it's an indicator item
	private function __saveFailedUuids($array, &$failedAttributes) {
		foreach ($array as $current => $value) {
			if (is_array($value)) {
				if (isset($value['Context'])) {
					array_push($failedAttributes, $value);
				} else {
					$this->__saveFailedUuids($value, $failedAttributes);
				}
			}
		}
	}
}
?>