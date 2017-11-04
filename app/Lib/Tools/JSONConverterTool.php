<?php
class JSONConverterTool {

	public function generateTop() {
		return '{"response":[';
	}

	public function generateBottom() {
		return ']}' . PHP_EOL;
	}

	public function convert($event, $isSiteAdmin=false) {
		$toRearrange = array('Org', 'Orgc', 'SharingGroup', 'Attribute', 'ShadowAttribute', 'RelatedAttribute', 'RelatedEvent', 'Galaxy', 'Object');
		foreach ($toRearrange as $object) {
			if (isset($event[$object])) {
				$event['Event'][$object] = $event[$object];
				unset($event[$object]);
			}
			if ($object == 'SharingGroup' && isset($event['Event']['SharingGroup']) && empty($event['Event']['SharingGroup'])) {
				unset($event['Event']['SharingGroup']);
			}
			if ($object == 'Galaxy') {
				foreach ($event['Event']['Galaxy'] as $k => $galaxy) {
					foreach ($galaxy['GalaxyCluster'] as $k2 => $cluster){
						if (empty($cluster['meta'])) {
							$event['Event']['Galaxy'][$k]['GalaxyCluster'][$k2]['meta'] = new stdclass();
						}
					}
				}
			}
		}

		if (isset($event['EventTag'])) {
			foreach ($event['EventTag'] as $k => $tag) {
				unset($tag['Tag']['org_id']);
				$event['Event']['Tag'][$k] = $tag['Tag'];
			}
		}

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
			$event['Event']['Attribute'] = $this->__cleanAttributes($event['Event']['Attribute']);
			if (!empty($event['Sighting'])) {
				foreach ($event['Event']['Attribute'] as $ak => $attribute) {
					foreach ($event['Sighting'] as $as => $sighting) {
						if ($attribute['id'] == $sighting['attribute_id']) {
							$event['Event']['Attribute'][$ak]['Sighting'][] = $sighting;
						}
					}
				}
				unset($event['Sighting']);
			}
		}
		if (isset($event['Event']['Object'])) {
			$event['Event']['Object'] = $this->__cleanObjects($event['Event']['Object']);
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

	private function __cleanAttributes($attributes) {
		// remove value1 and value2 from the output and remove invalid utf8 characters for the xml parser
		foreach ($attributes as $key => $value) {
			if (isset($value['SharingGroup']) && empty($value['SharingGroup'])) {
				unset($attributes[$key]['SharingGroup']);
			}
			unset($attributes[$key]['value1']);
			unset($attributes[$key]['value2']);
			unset($attributes[$key]['category_order']);
			if (isset($event['RelatedAttribute'][$value['id']])) {
				$attributes[$key]['RelatedAttribute'] = $event['Event']['RelatedAttribute'][$value['id']];
				foreach ($attributes[$key]['RelatedAttribute'] as &$ra) {
					$ra = array('Attribute' => $ra);
				}
			}
			if (isset($attributes[$key]['AttributeTag'])) {
				foreach ($attributes[$key]['AttributeTag'] as $atk => $tag) {
					unset($tag['Tag']['org_id']);
					$attributes[$key]['Tag'][$atk] = $tag['Tag'];
				}
				unset($attributes[$key]['AttributeTag']);
			}
		}
		return $attributes;
	}

	private function __cleanObjects($objects) {
		foreach ($objects as $k => $object) {
			if (!empty($object['Attribute'])) {
				$objects[$k]['Attribute'] = $this->__cleanAttributes($object['Attribute']);
			} else {
				unset($objects[$k]);
			}
		}
		$objects = array_values($objects);
		return $objects;
	}

	public function arrayPrinter($array, $root = true) {
		if (is_array($array)) {
			$resultArray = array();
			foreach ($array as $k => $element) {
				$temp = $this->arrayPrinter($element, false);
				if (!is_array($temp)) {
					$resultArray[] = '[' . $k .']' . $temp;
				} else {
					foreach ($temp as $t) $resultArray[] = '[' . $k . ']' . $t;
				}
			}
		} else $resultArray = ': ' . $array . PHP_EOL;
		if ($root) {
			$text = '';
			foreach ($resultArray as $r) $text .= $r;
			return $text;
		} else return $resultArray;
	}

	public function eventCollection2Format($events, $isSiteAdmin=false) {
		$results = array();
		foreach ($events as $event) $results[] = $this->convert($event, $isSiteAdmin);
		return implode(',' . PHP_EOL, $results);
	}

	public function frameCollection($input, $mispVersion = false) {
		$result = '{"response":[';
		$result .= $input;
		if ($mispVersion) $result .= ',' . PHP_EOL . '{"xml_version":"' . $mispVersion . '"}' . PHP_EOL;
		return $result . ']}';
	}
}
