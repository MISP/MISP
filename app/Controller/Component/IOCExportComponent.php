<?php

class IOCExportComponent extends Component {

	private $final = array();

	public function buildAll($event, $isSiteAdmin, $isMyEvent) {
		$temp = array();
		if (!$isSiteAdmin) {
			if (!$isMyEvent) {
				if ($event['Event']['distribution'] == 0) {
				throw new Exception('Nothing to see here (not authorised)');
				}
			}
		}
		$this->__buildTop($event);
		foreach ($event['Attribute'] as &$attribute) {
			if ($isSiteAdmin || $isMyEvent || $attribute['distribution'] > 0) {
				$this->__buildAttribute($attribute);
			}
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
		$this->final[] = '  <authored_by>' . h($event['Event']['orgc']) . '</authored_by>';
		$this->final[] = '  <authored_date>' . h($event['Event']['date']) . '</authored_date>';
		$this->final[] = '  <links />';
		$this->final[] = '  <definition>';
		// for now, since we don't have any logical links between attributes, we'll OR all of them
		$this->final[] = '    <Indicator operator="OR" id="' . h($event['Event']['uuid']) . '">';
	}

	// This method will turn each eligible attribute into an indicator
	private function __buildAttribute($attribute) {
		// Hop over attributes that don't have the to ids flag turned on and check whether the attribute is sent for IOC export based on category/type
		if (!$this->__checkValidTypeForIOC($attribute) || $attribute['to_ids'] == 0) return;

		// Composite type regkey|value doesn\t need the leading and closing IndicatorItem, so taken outside of the switch
		if ($attribute['type'] == 'regkey|value') {
			$this->final[] = '    	<Indicator operator="AND" id="' . h($attribute['uuid']) . '">';
			$this->final[] = '          <IndicatorItem id="' . h($attribute['uuid']) . '" condition="is">';
			$this->final[] = '            <Context document="Network" search="RegistryItem/KeyPath" type="mir" />';
			$this->final[] = '            <Content type="string">' . h($attribute['value1']) . '</Content>';
			$this->final[] = '          </IndicatorItem>';
			$this->final[] = '          <IndicatorItem id="' . h($attribute['uuid']) . '" condition="is">';
			$this->final[] = '            <Context document="Network" search="RegistryItem/Value" type="mir" />';
			$this->final[] = '            <Content type="string">' . h($attribute['value2']) . '</Content>';
			$this->final[] = '          </IndicatorItem>';
			$this->final[] = '        </Indicator>';
		} else {
			// for all other types
			$this->final[] = '      <IndicatorItem id="' . h($attribute['uuid']) . '" condition="is">';
		}
		// main switch to convert attributes to the IOC indicator equivalent
		switch ($attribute['type']) {
			case 'md5':
				$this->final[] = '        <Context document="FileItem" search="FileItem/Md5sum" type="mir" />';
				$this->final[] = '        <Content type="md5">' . h($attribute['value']) . '</Content>';
				break;
			case 'sha1':
				$this->final[] = '        <Context document="TaskItem" search="TaskItem/sha1sum" type="mir" />';
				$this->final[] = '        <Content type="string">' . h($attribute['value']) . '</Content>';
				break;
			case 'sha256':
				$this->final[] = '        <Context document="TaskItem" search="TaskItem/sha256sum" type="mir" />';
				$this->final[] = '        <Content type="string">' . h($attribute['value']) . '</Content>';
				break;
			case 'filename':
				$this->final[] = '        <Context document="FileItem" search="FileItem/FileName" type="mir" />';
				$this->final[] = '        <Content type="string">' . h($attribute['value']) . '</Content>';
				break;
			case 'filename|md5':
				$this->final[] = '        <Context document="FileItem" search="FileItem/Md5sum" type="mir" />';
				$this->final[] = '        <Content type="md5">' . h($attribute['value2']) . '</Content>';
				break;
			case 'filename|sha1':
				$this->final[] = '        <Context document="TaskItem" search="TaskItem/sha1sum" type="mir" />';
				$this->final[] = '        <Content type="string">' . h($attribute['value2']) . '</Content>';
				break;
			case 'filename|sha256':
				$this->final[] = '        <Context document="TaskItem" search="TaskItem/sha256sum" type="mir" />';
				$this->final[] = '        <Content type="string">' . h($attribute['value2']) . '</Content>';
				break;
			case 'ip-src':
				$this->final[] = '        <Context document="PortItem" search="PortItem/remoteIP" type="mir" />';
				$this->final[] = '        <Content type="IP">' . h($attribute['value']) . '</Content>';
				break;
			case 'ip-dst':
				$this->final[] = '        <Context document="RouteEntryItem" search="RouteEntryItem/Destination" type="mir" />';
				$this->final[] = '        <Content type="IP">' . h($attribute['value']) . '</Content>';
				break;
			case 'hostname':
				$this->final[] = '        <Context document="RouteEntryItem" search="RouteEntryItem/Destination" type="mir" />';
				$this->final[] = '        <Content type="string">' . h($attribute['value']) . '</Content>';
				break;
			case 'email-src':
				$this->final[] = '        <Context document="Email" search="Email/From" type="mir" />';
				$this->final[] = '        <Content type="string">' . h($attribute['value']) . '</Content>';
				break;
			case 'email-dst':
				$this->final[] = '        <Context document="Email" search="Email/To" type="mir" />';
				$this->final[] = '        <Content type="string">' . h($attribute['value']) . '</Content>';
				break;
			case 'email-subject':
				$this->final[] = '        <Context document="Email" search="Email/Subject" type="mir" />';
				$this->final[] = '        <Content type="string">' . h($attribute['value']) . '</Content>';
				break;
			case 'email-attachment':
				$this->final[] = '        <Context document="Email" search="Email/Attachment/Name" type="mir" />';
				$this->final[] = '        <Content type="string">' . h($attribute['value']) . '</Content>';
				break;
			case 'domain':
				$this->final[] = '        <Context document="Network" search="Network/DNS" type="mir" />';
				$this->final[] = '        <Content type="string">' . h($attribute['value']) . '</Content>';
				break;
			case 'url':
				$this->final[] = '        <Context document="UrlHistoryItem" search="UrlHistoryItem/URL" type="mir" />';
				$this->final[] = '        <Content type="string">' . h($attribute['value']) . '</Content>';
				break;
			case 'user-agent':
				$this->final[] = '        <Context document="Network" search="Network/UserAgent" type="mir" />';
				$this->final[] = '        <Content type="string">' . h($attribute['value']) . '</Content>';
				break;
			case 'regkey':
				$this->final[] = '        <Context document="Network" search="RegistryItem/KeyPath" type="mir" />';
				$this->final[] = '        <Content type="string">' . h($attribute['value']) . '</Content>';
				break;
			case 'snort':
				$this->final[] = '        <Context document="Snort" search="Snort/Snort" type="mir" />';
				$this->final[] = '        <Content type="string">' . h($attribute['value']) . '</Content>';
				break;
			case 'attachment':
				$this->final[] = '        <Context document="FileItem" search="FileItem/FileName" type="mir" />';
				$this->final[] = '        <Content type="string">' . h($attribute['value']) . '</Content>';
				break;
			case 'malware-sample':
				$this->final[] = '        <Context document="FileItem" search="FileItem/Md5sum" type="mir" />';
				$this->final[] = '        <Content type="md5">' . h($attribute['value2']) . '</Content>';
				break;
			case 'link':
				$this->final[] = '        <Context document="URL" search="UrlHistoryItem/URL" type="mir" />';
				$this->final[] = '        <Content type="md5">' . h($attribute['value2']) . '</Content>';
				break;
		}
		// since regkey|value is enclosed by an AND indicator, it was closed differently in its branch
		if ($attribute['type'] != 'regkey|value') {
			$this->final[] = '      </IndicatorItem>';
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
		// types that should be excluded
		$skipType = array('AS', 'pattern-in-file', 'pattern-in-traffic', 'pattern-in-memory', 'yara', 'vulnerability', 'comment', 'text', 'other');
		if (!in_array($attribute['category'], $Category)) return false;
		if (in_array($attribute['type'], $skipType)) return false;
		return true;
	}
}
