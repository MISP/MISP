<?php
class XMLConverterTool {
	public function recursiveEcho($array) {
		//debug($array);
		$text = "";
		foreach ($array as $k => $v) {
			if (is_array($v)) {
				if (empty($v)) $text .= '<' . $k . '/>';
				else {
					foreach ($v as $element) {
						$text .= '<' . $k . '>';
						$text .= $this->recursiveEcho($element);
						$text .= '</' . $k . '>';
					}
				}
			} else {
				if ($v === false) $v = 0;
				if ($v === "" || $v === null) $text .= '<' . $k . '/>';
				else {
					$text .= '<' . $k . '>' . $v . '</' . $k . '>';
				}
			}
		}
		return $text;
	}
	
	public function event2xmlArray($event, $isSiteAdmin=false) {
		$toEscape = array("&", "<", ">", "\"", "'");
		$escapeWith = array('&amp;', '&lt;', '&gt;', '&quot;', '&apos;');
		$event['Event']['Org'][0] = $event['Org'];
		$event['Event']['Orgc'][0] = $event['Orgc'];
		if (isset($event['SharingGroup']['SharingGroupOrg'])) {
			foreach ($event['SharingGroup']['SharingGroupOrg'] as $key => $sgo) {
				$event['SharingGroup']['SharingGroupOrg'][$key]['Organisation'] = array(0 => $event['SharingGroup']['SharingGroupOrg'][$key]['Organisation']);
			}
		}
		if (isset($event['SharingGroup']['SharingGroupServer'])) {
			foreach ($event['SharingGroup']['SharingGroupServer'] as $key => $sgs) {
				$event['SharingGroup']['SharingGroupServer'][$key]['Server'] = array(0 => $event['SharingGroup']['SharingGroupServer'][$key]['Server']);
			}
		}
		if (isset($event['SharingGroup'])) {
			$event['Event']['SharingGroup'][0] = $event['SharingGroup'];
		}
		$event['Event']['Attribute'] = $event['Attribute'];
		$event['Event']['ShadowAttribute'] = $event['ShadowAttribute'];
		
		if (isset($event['RelatedEvent'])) $event['Event']['RelatedEvent'] = $event['RelatedEvent'];
		
		// legacy
		unset($event['Event']['org']);
		unset($event['Event']['orgc']);
	
		if (isset($event['EventTag'])) {
			foreach ($event['EventTag'] as $k => $tag) {
				$event['Event']['Tag'][$k] = $tag['Tag'];
			}
		}
		
		$event['Event']['info'] = preg_replace ('/[^\x{0009}\x{000a}\x{000d}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}]+/u', ' ', $event['Event']['info']);
		$event['Event']['info'] = str_replace($toEscape, $escapeWith, $event['Event']['info']);
		//
		// cleanup the array from things we do not want to expose
		//
		unset($event['Event']['user_id'], $event['Event']['proposal_email_lock'], $event['Event']['locked'], $event['Event']['attribute_count']);
		// hide the org field is we are not in showorg mode
		if (!Configure::read('MISP.showorg') && !$isSiteAdmin) {
			unset($event['Event']['Org'], $event['Event']['Orgc'], $event['Event']['from']);
		}
		
		if (isset($event['Event']['Attribute'])) {
			// remove value1 and value2 from the output and remove invalid utf8 characters for the xml parser
			foreach ($event['Event']['Attribute'] as $key => $value) {
				$event['Event']['Attribute'][$key]['value'] = preg_replace ('/[^\x{0009}\x{000a}\x{000d}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}]+/u', ' ', $event['Event']['Attribute'][$key]['value']);
				$event['Event']['Attribute'][$key]['value'] = str_replace($toEscape, $escapeWith, $event['Event']['Attribute'][$key]['value']);
				$event['Event']['Attribute'][$key]['comment'] = preg_replace ('/[^\x{0009}\x{000a}\x{000d}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}]+/u', ' ', $event['Event']['Attribute'][$key]['comment']);
				$event['Event']['Attribute'][$key]['comment'] = str_replace($toEscape, $escapeWith, $event['Event']['Attribute'][$key]['comment']);
				unset($event['Event']['Attribute'][$key]['value1'], $event['Event']['Attribute'][$key]['value2']);
				foreach($event['Event']['Attribute'][$key]['ShadowAttribute'] as $skey => $svalue) {
					$event['Event']['Attribute'][$key]['ShadowAttribute'][$skey]['value'] = preg_replace ('/[^\x{0009}\x{000a}\x{000d}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}]+/u', ' ', $event['Event']['Attribute'][$key]['ShadowAttribute'][$skey]['value']);
					$event['Event']['Attribute'][$key]['ShadowAttribute'][$skey]['value'] = str_replace($toEscape, $escapeWith, $event['Event']['Attribute'][$key]['ShadowAttribute'][$skey]['value']);
					$event['Event']['Attribute'][$key]['ShadowAttribute'][$skey]['comment'] = preg_replace ('/[^\x{0009}\x{000a}\x{000d}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}]+/u', ' ', $event['Event']['Attribute'][$key]['ShadowAttribute'][$skey]['comment']);
					$event['Event']['Attribute'][$key]['ShadowAttribute'][$skey]['comment'] = str_replace($toEscape, $escapeWith, $event['Event']['Attribute'][$key]['ShadowAttribute'][$skey]['comment']);
				}
				if (isset($event['Event']['Attribute'][$key]['SharingGroup']['SharingGroupOrg'])) {
					foreach ($event['Event']['Attribute'][$key]['SharingGroup']['SharingGroupOrg'] as $k => $sgo) {
						$event['Event']['Attribute'][$key]['SharingGroup']['SharingGroupOrg'][$k]['Organisation'] = array(0 => $event['Event']['Attribute'][$key]['SharingGroup']['SharingGroupOrg'][$k]['Organisation']);
					}
				}
				if (isset($event['Event']['Attribute'][$key]['SharingGroup']['SharingGroupServer'])) {
					foreach ($event['Event']['Attribute'][$key]['SharingGroup']['SharingGroupServer'] as $k => $sgs) {
						$event['Event']['Attribute'][$key]['SharingGroup']['SharingGroupServer'][$k]['Server'] = array(0 => $event['Event']['Attribute'][$key]['SharingGroup']['SharingGroupServer'][$k]['Server']);
					}
				}
				if (isset($event['Event']['Attribute'][$key]['SharingGroup'])) {
					$event['Event']['Attribute'][$key]['SharingGroup'][0] = $event['Event']['Attribute'][$key]['SharingGroup'];
					unset($event['Event']['Attribute'][$key]['SharingGroup']);
				}
			}
		}
		
		if (isset($event['Event']['ShadowAttribute'])) {
			// remove invalid utf8 characters for the xml parser
			foreach($event['Event']['ShadowAttribute'] as $key => $value) {
				$event['Event']['ShadowAttribute'][$key]['value'] = preg_replace ('/[^\x{0009}\x{000a}\x{000d}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}]+/u', ' ', $event['Event']['ShadowAttribute'][$key]['value']);
				$event['Event']['ShadowAttribute'][$key]['value'] = str_replace($toEscape, $escapeWith, $event['Event']['ShadowAttribute'][$key]['value']);
				$event['Event']['ShadowAttribute'][$key]['comment'] = preg_replace ('/[^\x{0009}\x{000a}\x{000d}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}]+/u', ' ', $event['Event']['ShadowAttribute'][$key]['comment']);
				$event['Event']['ShadowAttribute'][$key]['comment'] = str_replace($toEscape, $escapeWith, $event['Event']['ShadowAttribute'][$key]['comment']);
			}
		}

		if (isset($event['Event']['RelatedEvent'])) {
			foreach ($event['Event']['RelatedEvent'] as $key => $value) {
				$temp = $value['Event'];
				unset($event['Event']['RelatedEvent'][$key]['Event']);
				$event['Event']['RelatedEvent'][$key]['Event'][0] = $temp;
				unset($event['Event']['RelatedEvent'][$key]['Event'][0]['user_id']);
				$event['Event']['RelatedEvent'][$key]['Event'][0]['info'] = preg_replace ('/[^\x{0009}\x{000a}\x{000d}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}]+/u', ' ', $event['Event']['RelatedEvent'][$key]['Event'][0]['info']);
				$event['Event']['RelatedEvent'][$key]['Event'][0]['info'] = str_replace($toEscape, $escapeWith, $event['Event']['RelatedEvent'][$key]['Event'][0]['info']);
				if (!Configure::read('MISP.showorg') && !$isSiteAdmin) {
					unset($event['Event']['RelatedEvent'][$key]['Org'], $event['Event']['RelatedEvent'][$key]['Orgc']);
				} else {
					$event['Event']['RelatedEvent'][$key]['Event'][0]['Org'][0] = $event['Event']['RelatedEvent'][$key]['Org'];
					$event['Event']['RelatedEvent'][$key]['Event'][0]['Orgc'][0] = $event['Event']['RelatedEvent'][$key]['Orgc'];
					unset ($event['Event']['RelatedEvent'][$key]['Org'], $event['Event']['RelatedEvent'][$key]['Orgc']);
				}
				unset($temp);
			}
		}
		return array('Event' => $event['Event']);
	}
	
	public function event2XML($event, $isSiteAdmin=false) {
		$xmlArray = $this->event2xmlArray($event, $isSiteAdmin);
		return $this->recursiveEcho(array('Event' => array(0 => $xmlArray['Event'])));
	}
}