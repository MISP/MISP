<?php
$xmlArray = array();
$toEscape = array("&", "<", ">", "\"", "'");
$escapeWith = array('&amp;', '&lt;', '&gt;', '&quot;', '&apos;');
foreach ($results as $result) {
	$result['Event']['Attribute'] = $result['Attribute'];
	$result['Event']['ShadowAttribute'] = $result['ShadowAttribute'];
	$result['Event']['RelatedEvent'] = $result['RelatedEvent'];
	$result['Event']['info'] = preg_replace ('/[^\x{0009}\x{000a}\x{000d}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}]+/u', ' ', $result['Event']['info']);
	$result['Event']['info'] = str_replace($toEscape, $escapeWith, $result['Event']['info']);

	//
	// cleanup the array from things we do not want to expose
	//
	unset($result['Event']['user_id']);
	// hide the org field is we are not in showorg mode
	if (!Configure::read('MISP.showorg') && !$isSiteAdmin) {
		unset($result['Event']['org']);
		unset($result['Event']['orgc']);
		unset($result['Event']['from']);
	}
	// remove value1 and value2 from the output and remove invalid utf8 characters for the xml parser
	foreach ($result['Event']['Attribute'] as $key => $value) {
		$result['Event']['Attribute'][$key]['value'] = preg_replace ('/[^\x{0009}\x{000a}\x{000d}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}]+/u', ' ', $result['Event']['Attribute'][$key]['value']);
		$result['Event']['Attribute'][$key]['value'] = str_replace($toEscape, $escapeWith, $result['Event']['Attribute'][$key]['value']);
		$result['Event']['Attribute'][$key]['comment'] = preg_replace ('/[^\x{0009}\x{000a}\x{000d}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}]+/u', ' ', $result['Event']['Attribute'][$key]['comment']);
		$result['Event']['Attribute'][$key]['comment'] = str_replace($toEscape, $escapeWith, $result['Event']['Attribute'][$key]['comment']);
		unset($result['Event']['Attribute'][$key]['value1']);
		unset($result['Event']['Attribute'][$key]['value2']);
		unset($result['Event']['Attribute'][$key]['category_order']);
		foreach($result['Event']['Attribute'][$key]['ShadowAttribute'] as $skey => $svalue) {
			$result['Event']['Attribute'][$key]['ShadowAttribute'][$skey]['value'] = preg_replace ('/[^\x{0009}\x{000a}\x{000d}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}]+/u', ' ', $result['Event']['Attribute'][$key]['ShadowAttribute'][$skey]['value']);
			$result['Event']['Attribute'][$key]['ShadowAttribute'][$skey]['value'] = str_replace($toEscape, $escapeWith, $result['Event']['Attribute'][$key]['ShadowAttribute'][$skey]['value']);
			$result['Event']['Attribute'][$key]['ShadowAttribute'][$skey]['comment'] = preg_replace ('/[^\x{0009}\x{000a}\x{000d}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}]+/u', ' ', $result['Event']['Attribute'][$key]['ShadowAttribute'][$skey]['comment']);
			$result['Event']['Attribute'][$key]['ShadowAttribute'][$skey]['comment'] = str_replace($toEscape, $escapeWith, $result['Event']['Attribute'][$key]['ShadowAttribute'][$skey]['comment']);
		}
	}
	// remove invalid utf8 characters for the xml parser
	foreach($result['Event']['ShadowAttribute'] as $key => $value) {
		$result['Event']['ShadowAttribute'][$key]['value'] = preg_replace ('/[^\x{0009}\x{000a}\x{000d}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}]+/u', ' ', $result['Event']['ShadowAttribute'][$key]['value']);
		$result['Event']['ShadowAttribute'][$key]['value'] = str_replace($toEscape, $escapeWith, $result['Event']['ShadowAttribute'][$key]['value']);
		$result['Event']['ShadowAttribute'][$key]['comment'] = preg_replace ('/[^\x{0009}\x{000a}\x{000d}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}]+/u', ' ', $result['Event']['ShadowAttribute'][$key]['comment']);
		$result['Event']['ShadowAttribute'][$key]['comment'] = str_replace($toEscape, $escapeWith, $result['Event']['ShadowAttribute'][$key]['comment']);	
	}
	
	if (isset($result['Event']['RelatedEvent'])) {
		foreach ($result['Event']['RelatedEvent'] as $key => $value) {
			$temp = $value['Event'];
			unset($result['Event']['RelatedEvent'][$key]['Event']);
			$result['Event']['RelatedEvent'][$key]['Event'][0] = $temp;
			unset($result['Event']['RelatedEvent'][$key]['Event'][0]['user_id']);
			$result['Event']['RelatedEvent'][$key]['Event'][0]['info'] = preg_replace ('/[^\x{0009}\x{000a}\x{000d}\x{0020}-\x{D7FF}\x{E000}-\x{FFFD}]+/u', ' ', $result['Event']['RelatedEvent'][$key]['Event'][0]['info']);
			$result['Event']['RelatedEvent'][$key]['Event'][0]['info'] = str_replace($toEscape, $escapeWith, $result['Event']['RelatedEvent'][$key]['Event'][0]['info']);
			if (!Configure::read('MISP.showorg') && !$isAdmin) {
				unset($result['Event']['RelatedEvent'][$key]['Event'][0]['org']);
				unset($result['Event']['RelatedEvent'][$key]['Event'][0]['orgc']);
			}
			unset($temp);
		}
	}
	$xmlArray['response']['Event'][] = $result['Event'];
}

echo '<?xml version="1.0" encoding="UTF-8"?>' . PHP_EOL . '<response>';
echo $this->XmlOutput->recursiveEcho($xmlArray['response']);
echo '<xml_version>' . $mispVersion . '</xml_version>';
echo '</response>' . PHP_EOL;
