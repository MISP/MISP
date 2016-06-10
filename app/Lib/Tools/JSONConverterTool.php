<?php
class JSONConverterTool {
	public function event2JSON($event, $isSiteAdmin=false) {
		$event['Event']['Org'] = $event['Org'];
		$event['Event']['Orgc'] = $event['Orgc'];
		if (isset($event['SharingGroup'])) $event['Event']['SharingGroup'] = $event['SharingGroup'];
		$event['Event']['Attribute'] = $event['Attribute'];
		$event['Event']['ShadowAttribute'] = $event['ShadowAttribute'];
		$event['Event']['RelatedEvent'] = $event['RelatedEvent'];

		if (isset($event['EventTag'])) {
			foreach ($event['EventTag'] as $k => $tag) {
				$event['Event']['Tag'][$k] = $tag['Tag'];
			}
		}

		if (isset($event['RelatedAttribute'])) $event['Event']['RelatedAttribute'] = $event['RelatedAttribute'];
		else $event['Event']['RelatedAttribute'] = array();
		//
		// cleanup the array from things we do not want to expose
		//
		unset($event['Event']['user_id']);
		// hide the org field is we are not in showorg mode
		if (!Configure::read('MISP.showorg') && !$isSiteAdmin) {
			unset($event['Event']['org']);
			unset($event['Event']['orgc']);
			unset($event['Event']['from']);
		}

		if (isset($event['Event']['Attribute'])) {
			// remove value1 and value2 from the output and remove invalid utf8 characters for the xml parser
			foreach ($event['Event']['Attribute'] as $key => $value) {
				unset($event['Event']['Attribute'][$key]['value1']);
				unset($event['Event']['Attribute'][$key]['value2']);
				unset($event['Event']['Attribute'][$key]['category_order']);
				if (isset($event['RelatedAttribute'][$value['id']])) {
					$event['Event']['Attribute'][$key]['RelatedAttribute'] = $event['Event']['RelatedAttribute'][$value['id']];
					foreach ($event['Event']['Attribute'][$key]['RelatedAttribute'] as &$ra) {
						$ra = array('Attribute' => $ra);
					}
				}
			}
		}
		unset($event['Event']['RelatedAttribute']);
		if (isset($event['Event']['RelatedEvent'])) {
			foreach ($event['Event']['RelatedEvent'] as $key => $value) {
				unset($event['Event']['RelatedEvent'][$key]['Event']['user_id']);
				if (!Configure::read('MISP.showorg') && !$isSiteAdmin) {
					unset($event['Event']['RelatedEvent'][$key]['Event']['org']);
					unset($event['Event']['RelatedEvent'][$key]['Event']['orgc']);
				}
			}
		}
		$result = array('Event' => $event['Event']);
		if (isset($event['errors'])) $result = array_merge($result, array('errors' => $event['errors']));
		return json_encode($result, JSON_PRETTY_PRINT);
	}

	public function arrayPrinter($array, $root = true) {
		if (is_array($array)) {
			$resultArray = array();
			foreach ($array as $k => $element) {
				$temp = $this->arrayPrinter($element, false);
				if (!is_array($temp)) {
					$resultArray[] = '[' . $k .']' . $temp;
				} else {
					foreach ($temp as &$t) $resultArray[] = '[' . $k . ']' . $t;
				}
			}
		} else $resultArray = ': ' . $array . PHP_EOL;
		if ($root) {
			$text = '';
			foreach ($resultArray as &$r) $text .= $r;
			return $text;
		} else return $resultArray;
	}

	public function eventCollection2Format($events, $isSiteAdmin=false) {
		$results = array();
		foreach ($events as &$event) $results[] = $this->event2JSON($event, $isSiteAdmin);
		return implode(',' . PHP_EOL, $results);
	}

	public function frameCollection($input, $mispVersion = false) {
		$result = '{"response":[';
		$result .= $input;
		if ($mispVersion) $result .= ',' . PHP_EOL . '{"xml_version":"' . $mispVersion . '"}' . PHP_EOL;
		return $result . ']}';
	}
}
