<?php

class NidsExport {

	public $rules = array();

	public $classtype = 'trojan-activity';

	public $format = "";   // suricata (default), snort

	public function explain() {
		$this->rules[] = '# MISP export of IDS rules - optimized for '.$this->format;
		$this->rules[] = '#';
		$this->rules[] = '# These NIDS rules contain some variables that need to exist in your configuration.';
		$this->rules[] = '# Make sure you have set:';
		$this->rules[] = '#';
		$this->rules[] = '# $HOME_NET	- Your internal network range';
		$this->rules[] = '# $EXTERNAL_NET - The network considered as outside';
		$this->rules[] = '# $SMTP_SERVERS - All your internal SMTP servers';
		$this->rules[] = '# $HTTP_PORTS   - The ports used to contain HTTP traffic (not required with suricata export)';
		$this->rules[] = '# ';
	}

	private $whitelist = null;


	public function export($items, $startSid, $format="suricata", $continue = false) {
		$this->format = $format;
		$this->Whitelist = ClassRegistry::init('Whitelist');
		$this->whitelist = $this->Whitelist->getBlockedValues();

		// output a short explanation
		if (!$continue) {
			$this->explain();
		}
		// generate the rules
		foreach ($items as $item) {
			// retrieve all tags for this item to add them to the msg
			$tagsArray = [];
			foreach ($item['AttributeTag'] as $tag_attr) {
				if (array_key_exists('name', $tag_attr['Tag'])) {
					array_push($tagsArray, $tag_attr['Tag']['name']);
				}
			}
			$ruleFormatMsgTags = implode(",", $tagsArray);

			# proto src_ip src_port direction dst_ip dst_port msg rule_content tag sid rev
			$ruleFormatMsg = 'msg: "MISP e' . $item['Event']['id'] . ' [' . $ruleFormatMsgTags . '] %s"';
			$ruleFormatReference = 'reference:url,' . Configure::read('MISP.baseurl') . '/events/view/' . $item['Event']['id'];
			$ruleFormat = '%salert %s %s %s %s %s %s (' . $ruleFormatMsg . '; %s %s classtype:' . $this->classtype . '; sid:%d; rev:%d; priority:' . $item['Event']['threat_level_id'] . '; ' . $ruleFormatReference . ';) ';

			$sid = $startSid + ($item['Attribute']['id'] * 10); // leave 9 possible rules per attribute type
			$sid++;
			switch ($item['Attribute']['type']) {
				// LATER nids - test all the snort attributes
				// LATER nids - add the tag keyword in the rules to capture network traffic
				// LATER nids - sanitize every $attribute['value'] to not conflict with snort
				case 'ip-dst':
					$this->ipDstRule($ruleFormat, $item['Attribute'], $sid);
					break;
				case 'ip-src':
					$this->ipSrcRule($ruleFormat, $item['Attribute'], $sid);
					break;
				case 'ip-dst|port':
					$this->ipDstRule($ruleFormat, $item['Attribute'], $sid);
					break;
				case 'ip-src|port':
					$this->ipSrcRule($ruleFormat, $item['Attribute'], $sid);
					break;
				case 'email-src':
					$this->emailSrcRule($ruleFormat, $item['Attribute'], $sid);
					break;
				case 'email-dst':
					$this->emailDstRule($ruleFormat, $item['Attribute'], $sid);
					break;
				case 'email-subject':
					$this->emailSubjectRule($ruleFormat, $item['Attribute'], $sid);
					break;
				case 'email-attachment':
					$this->emailAttachmentRule($ruleFormat, $item['Attribute'], $sid);
					break;
				case 'domain':
					$this->domainRule($ruleFormat, $item['Attribute'], $sid);
					break;
				case 'domain|ip':
					$this->domainIpRule($ruleFormat, $item['Attribute'], $sid);
					break;
				case 'hostname':
					$this->hostnameRule($ruleFormat, $item['Attribute'], $sid);
					break;
				case 'url':
					$this->urlRule($ruleFormat, $item['Attribute'], $sid);
					break;
				case 'user-agent':
					$this->userAgentRule($ruleFormat, $item['Attribute'], $sid);
					break;
				case 'snort':
					$this->snortRule($ruleFormat, $item['Attribute'], $sid, $ruleFormatMsg, $ruleFormatReference);
				default:
					break;
			}

		}
		return $this->rules;
	}
	
	public function domainIpRule($ruleFormat, $attribute, &$sid) {
		$values = explode('|', $attribute['value']);
		$attributeCopy = $attribute;
		$attributeCopy['value'] = $values[0];
		$this->domainRule($ruleFormat, $attributeCopy, $sid);
		$sid++;
		$attributeCopy['value'] = $values[1];
		$this->ipDstRule($ruleFormat, $attributeCopy, $sid);
		$sid++;
		$this->ipSrcRule($ruleFormat, $attributeCopy, $sid);
	}

	public function ipDstRule($ruleFormat, $attribute, &$sid) {
		$overruled = $this->checkWhitelist($attribute['value']);
		$ipport = NidsExport::getIpPort($attribute);
		$this->rules[] = sprintf($ruleFormat,
				($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
				'ip',							// proto
				'$HOME_NET',					// src_ip
				'any',							// src_port
				'->',							// direction
				$ipport[0],			// dst_ip
				$ipport[1],							// dst_port
				'Outgoing To IP: ' . $attribute['value'],		// msg
				'',								// rule_content
				'',								// tag
				$sid,							// sid
				1								// rev
				);
	}

	public function ipSrcRule($ruleFormat, $attribute, &$sid) {
		$overruled = $this->checkWhitelist($attribute['value']);
		$ipport = NidsExport::getIpPort($attribute);
		$this->rules[] = sprintf($ruleFormat,
				($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
				'ip',							// proto
				$ipport[0],			// src_ip
				$ipport[1],							// src_port
				'->',							// direction
				'$HOME_NET',					// dst_ip
				'any',							// dst_port
				'Incoming From IP: ' . $attribute['value'],		// msg
				'',								// rule_content
				'',								// tag
				$sid,							// sid
				1								// rev
				);
	}

	public function emailSrcRule($ruleFormat, $attribute, &$sid) {
		$overruled = $this->checkWhitelist($attribute['value']);
		$attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
		$content = 'flow:established,to_server; content:"MAIL FROM|3a|"; nocase; content:"' . $attribute['value'] . '"; fast_pattern; nocase; content:"|0D 0A 0D 0A|"; within:8192;';
		$this->rules[] = sprintf($ruleFormat,
				($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
				'tcp',							// proto
				'$EXTERNAL_NET',				// src_ip
				'any',							// src_port
				'->',							// direction
				'$SMTP_SERVERS',				// dst_ip
				'25',							// dst_port
				'Source Email Address: ' . $attribute['value'],		// msg
				$content,						// rule_content
				'tag:session,600,seconds;',		// tag
				$sid,							// sid
				1								// rev
				);
	}

	public function emailDstRule($ruleFormat, $attribute, &$sid) {
		$overruled = $this->checkWhitelist($attribute['value']);
		$attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
		$content = 'flow:established,to_server; content:"RCPT TO|3a|"; nocase; content:"' . $attribute['value'] . '"; fast_pattern; nocase; content:"|0D 0A 0D 0A|"; within:8192;';
		$this->rules[] = sprintf($ruleFormat,
				($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
				'tcp',							// proto
				'$EXTERNAL_NET',				// src_ip
				'any',							// src_port
				'->',							// direction
				'$SMTP_SERVERS',				// dst_ip
				'25',							// dst_port
				'Destination Email Address: ' . $attribute['value'],	// msg
				$content,						// rule_content
				'tag:session,600,seconds;',		// tag
				$sid,							// sid
				1								// rev
				);
	}

	public function emailSubjectRule($ruleFormat, $attribute, &$sid) {
		// LATER nids - email-subject rule might not match because of line-wrapping
		$overruled = $this->checkWhitelist($attribute['value']);
		$attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
		$content = 'flow:established,to_server; content:"Subject|3a|"; nocase; content:"' . $attribute['value'] . '"; fast_pattern; nocase; content:"|0D 0A 0D 0A|"; within:8192;';
		$this->rules[] = sprintf($ruleFormat,
				($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
				'tcp',							// proto
				'$EXTERNAL_NET',				// src_ip
				'any',							// src_port
				'->',							// direction
				'$SMTP_SERVERS',				// dst_ip
				'25',							// dst_port
				'Bad Email Subject',			// msg
				$content,						// rule_content
				'tag:session,600,seconds;',		// tag
				$sid,							// sid
				1								// rev
				);
	}

	public function emailAttachmentRule($ruleFormat, $attribute, &$sid) {
		// LATER nids - email-attachment rule might not match because of line-wrapping
		$overruled = $this->checkWhitelist($attribute['value']);
		$attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
		$content = 'flow:established,to_server; content:"Content-Disposition|3a| attachment|3b| filename|3d 22|"; content:"' . $attribute['value'] . '|22|"; fast_pattern; content:"|0D 0A 0D 0A|"; within:8192;';
		$this->rules[] = sprintf($ruleFormat,
				($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
				'tcp',							// proto
				'$EXTERNAL_NET',				// src_ip
				'any',							// src_port
				'->',							// direction
				'$SMTP_SERVERS',				// dst_ip
				'25',							// dst_port
				'Bad Email Attachment',			// msg
				$content,						// rule_content	// LATER nids - test and finetune this snort rule https://secure.wikimedia.org/wikipedia/en/wiki/MIME#Content-Disposition
				'tag:session,600,seconds;',		// tag
				$sid,							// sid
				1								// rev
				);
	}

	public function hostnameRule($ruleFormat, $attribute, &$sid) {
		$overruled = $this->checkWhitelist($attribute['value']);
		$attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
		$content = 'content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2; content:"' . NidsExport::dnsNameToRawFormat($attribute['value'], 'hostname') . '"; fast_pattern; nocase;';
		$this->rules[] = sprintf($ruleFormat,
				($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
				'udp',							// proto
				'any',							// src_ip
				'any',							// src_port
				'->',							// direction
				'any',							// dst_ip
				'53',							// dst_port
				'Hostname: ' . $attribute['value'],		// msg
				$content,						// rule_content
				'',								// tag
				$sid,							// sid
				1								// rev
		);
		$sid++;
		$this->rules[] = sprintf($ruleFormat,
				($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
				'tcp',							// proto
				'any',							// src_ip
				'any',							// src_port
				'->',							// direction
				'any',							// dst_ip
				'53',							// dst_port
				'Hostname: ' . $attribute['value'],		// msg
				$content. ' flow:established;',			// rule_content
				'',								// tag
				$sid,							// sid
				1								// rev
		);
		$sid++;
		// also do http requests
		$content = 'flow:to_server,established; content: "Host|3a| ' . $attribute['value'] . '"; nocase; http_header; pcre: "/(^|[^A-Za-z0-9-\.])' . preg_quote($attribute['value']) . '[^A-Za-z0-9-\.]/H";';
		$this->rules[] = sprintf($ruleFormat,
			($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
				'tcp',						// proto
				'$HOME_NET',					// src_ip
				'any',							// src_port
				'->',							// direction
				'$EXTERNAL_NET',				// dst_ip
				'$HTTP_PORTS',					// dst_port
				'Outgoing HTTP Hostname: ' . $attribute['value'],		// msg
				$content,						// rule_content
				'tag:session,600,seconds;',		// tag
				$sid,							// sid
				1								// rev
		);
	}

	public function domainRule($ruleFormat, $attribute, &$sid) {
		$overruled = $this->checkWhitelist($attribute['value']);
		$attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
		$content = 'content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2; content:"' . NidsExport::dnsNameToRawFormat($attribute['value']) . '"; fast_pattern; nocase;';
		$this->rules[] = sprintf($ruleFormat,
				($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
				'udp',							// proto
				'any',							// src_ip
				'any',							// src_port
				'->',							// direction
				'any',							// dst_ip
				'53',							// dst_port
				'Domain: ' . $attribute['value'],		// msg
				$content,						// rule_content
				'',								// tag
				$sid,							// sid
				1								// rev
				);
		$sid++;
		$this->rules[] = sprintf($ruleFormat,
				($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
				'tcp',							// proto
				'any',							// src_ip
				'any',							// src_port
				'->',							// direction
				'any',							// dst_ip
				'53',							// dst_port
				'Domain: ' . $attribute['value'],		// msg
				$content. ' flow:established;',			// rule_content
				'',								// tag
				$sid,							// sid
				1								// rev
				);
		$sid++;
		// also do http requests,
		$content = 'flow:to_server,established; content: "Host|3a|"; nocase; http_header; content:"' . $attribute['value'] . '"; fast_pattern; nocase; http_header; pcre: "/(^|[^A-Za-z0-9-])' . preg_quote($attribute['value']) . '[^A-Za-z0-9-\.]/H";';
		$this->rules[] = sprintf($ruleFormat,
			($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
				'tcp',						// proto
				'$HOME_NET',					// src_ip
				'any',							// src_port
				'->',							// direction
				'$EXTERNAL_NET',				// dst_ip
				'$HTTP_PORTS',					// dst_port
				'Outgoing HTTP Domain: ' . $attribute['value'],		// msg
				$content,						// rule_content
				'tag:session,600,seconds;',		// tag
				$sid,							// sid
				1								// rev
		);
	}

	public function urlRule($ruleFormat, $attribute, &$sid) {
		// TODO in hindsight, an url should not be excluded given a host or domain name.
		//$hostpart = parse_url($attribute['value'], PHP_URL_HOST);
		//$overruled = $this->checkNames($hostpart);
		$overruled = $this->checkWhitelist($attribute['value']);
		$attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
		$content = 'flow:to_server,established; content:"' . $attribute['value'] . '"; nocase; http_uri;';
		$this->rules[] = sprintf($ruleFormat,
				($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
				'tcp',							// proto
				'$HOME_NET',					// src_ip
				'any',							// src_port
				'->',							// direction
				'$EXTERNAL_NET',				// dst_ip
				'$HTTP_PORTS',					// dst_port
				'Outgoing HTTP URL: ' . $attribute['value'],		// msg
				$content,						// rule_content
				'tag:session,600,seconds;',		// tag
				$sid,							// sid
				1								// rev
				);
	}

	public function userAgentRule($ruleFormat, $attribute, &$sid) {
		$overruled = $this->checkWhitelist($attribute['value']);
		$attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
		$content = 'flow:to_server,established; content:"' . $attribute['value'] . '"; http_header;';
		$this->rules[] = sprintf($ruleFormat,
				($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
				'tcp',						// proto
				'$HOME_NET',					// src_ip
				'any',							// src_port
				'->',							// direction
				'$EXTERNAL_NET',				// dst_ip
				'$HTTP_PORTS',					// dst_port
				'Outgoing User-Agent: ' . $attribute['value'],		// msg
				$content,						// rule_content
				'tag:session,600,seconds;',		// tag
				$sid,							// sid
				1								// rev
		);
	}

	public function snortRule($ruleFormat, $attribute, &$sid, $ruleFormatMsg, $ruleFormatReference) {
		// LATER nids - test using lots of snort rules, some rules don't contain all the necessary to be a valid rule.

		// store the value in the rule, but also strip out the newlines
		$tmpRule = str_replace(array("\r","\n"), " ", $attribute['value']);

		// rebuild the rule by overwriting the different keywords using preg_replace()
		//   sid	   - '/sid\s*:\s*[0-9]+\s*;/'
		//   rev	   - '/rev\s*:\s*[0-9]+\s*;/'
		//   classtype - '/classtype:[a-zA-Z_-]+;/'
		//   msg	   - '/msg\s*:\s*".*?"\s*;/'
		//   reference - '/reference\s*:\s*.+?;/'
		//   tag	   - '/tag\s*:\s*.+?;/'
		$replaceCount = array();
		$tmpRule = preg_replace('/sid\s*:\s*[0-9]+\s*;/', 'sid:' . $sid . ';', $tmpRule, -1, $replaceCount['sid']);
		if (null == $tmpRule) return false;	// don't output the rule on error with the regex
		$tmpRule = preg_replace('/rev\s*:\s*[0-9]+\s*;/', 'rev:1;', $tmpRule, -1, $replaceCount['rev']);
		if (null == $tmpRule) return false;	// don't output the rule on error with the regex
		$tmpRule = preg_replace('/classtype:[a-zA-Z_-]+;/', 'classtype:' . $this->classtype . ';', $tmpRule, -1, $replaceCount['classtype']);
		if (null == $tmpRule) return false;	// don't output the rule on error with the regex
		$tmpRule = preg_replace('/msg\s*:\s*"(.*?)"\s*;/', sprintf($ruleFormatMsg, 'snort-rule | $1') . ';', $tmpRule, -1, $replaceCount['msg']);
		if (null == $tmpRule) return false;	// don't output the rule on error with the regex
		$tmpRule = preg_replace('/reference\s*:\s*.+?;/', $ruleFormatReference . ';', $tmpRule, -1, $replaceCount['reference']);
		if (null == $tmpRule) return false;	// don't output the rule on error with the regex
		$tmpRule = preg_replace('/reference\s*:\s*.+?;/', $ruleFormatReference . ';', $tmpRule, -1, $replaceCount['reference']);
		if (null == $tmpRule) return false;	// don't output the rule on error with the regex
		// FIXME nids -  implement priority overwriting

		// some values were not replaced, so we need to add them ourselves, and insert them in the rule
		$extraForRule = "";
		if (0 == $replaceCount['sid']) {
			$extraForRule .= 'sid:' . $sid . ';';
		} if (0 == $replaceCount['rev']) {
			$extraForRule .= 'rev:1;';
		} if (0 == $replaceCount['classtype']) {
			$extraForRule .= 'classtype:' . $this->classtype . ';';
		} if (0 == $replaceCount['msg']) {
			$extraForRule .= $tmpMessage . ';';
		} if (0 == $replaceCount['reference']) {
			$extraForRule .= $ruleFormatReference . ';';
		}
		$tmpRule = preg_replace('/;\s*\)/', '; ' . $extraForRule . ')', $tmpRule);
		// finally the rule is cleaned up and can be outputed
		$this->rules[] = $tmpRule;
		return true;
	}

	/**
	 * Converts a DNS name to a raw format usable in NIDS like Snort.
	 *   example host: foobar.com becomes |00||06|foobar|03|com|00|
	 *   example domain: foobar.com becomes |06|foobar|03|com|00|
	 * @param string $name dns name to be converted
	 * @param string $type the type of dns name - domain (default) or hostname
	 * @return string raw snort compatible format of the dns name
	 */
	public static function dnsNameToRawFormat($name, $type='domain') {
		$rawName = "";
		if ('hostname' == $type) $rawName = '|00|';
		// explode using the dot
		$explodedNames = explode('.', $name);
		// for each part
		foreach ($explodedNames as $explodedName) {
			// count the lenght of the part, and add |length| before
			$length = strlen($explodedName);
			if ($length > 255) log('WARNING: DNS name is too long for RFC: '.$name);
			$hexLength = dechex($length);
			if (1 == strlen($hexLength)) $hexLength = '0' . $hexLength;
			$rawName .= '|' . $hexLength . '|' . $explodedName;
		}
		// put all together
		$rawName .= '|00|';
		// and append |00| to terminate the name
		return $rawName;
	}

	/**
	 * Converts a DNS name to a MS DNS log format.
	 * Practical usage is to use these strings to search in logfiles
	 *   example: foobar.com becomes (6)foobar(3)com(0)
	 * @param string $name dns name to be converted
	 * @return string raw snort compatible format of the dns name
	 */
	public static function dnsNameToMSDNSLogFormat($name) {
		$rawName = "";
		// in MS DNS log format we can't use (0) to distinguish between hostname and domain (including subdomains)
		// explode using the dot
		$explodedNames = explode('.', $name);
		// for each part
		foreach ($explodedNames as $explodedName) {
			// count the lenght of the part, and add |length| before
			$length = strlen($explodedName);
			if ($length > 255) log('WARNING: DNS name is too long for RFC: '.$name);
			$hexLength = dechex($length);
			$rawName .= '(' . $hexLength . ')' . $explodedName;
		}
		// put all together
		$rawName .= '(0)';
		// and append (0) to terminate the name
		return $rawName;
	}

	/**
	 * Replaces characters that are not allowed in a signature.
	 *   example: " is converted to |22|
	 * @param unknown_type $value
	 */
	public static function replaceIllegalChars($value) {
		$replace_pairs = array(
				'|' => '|7c|', // Needs to stay on top !
				'"' => '|22|',
				';' => '|3b|',
				':' => '|3a|',
				'\\' => '|5c|',
				'0x' => '|30 78|'
				);
		return strtr($value, $replace_pairs);
	}

	public function checkWhitelist($value) {
		foreach ($this->whitelist as $wlitem) {
			if (preg_match($wlitem, $value)) {
				return true;
			}
		}
		return false;
	}

	public static function getProtocolPort($protocol, $customPort) {
		if($customPort == null) {
		    switch ($protocol) {
			case "http":
			    return '$HTTP_PORTS';
			case "https":
			    return '443';
			case "ssh":
			    return '22';
			case "ftp":
			    return '[20,21]';
			default:
			    return 'any';
		    }
		} else {
		    return $customPort;
		}
	}

	public static function getCustomIP($customIP) {
		if(filter_var($customIP, FILTER_VALIDATE_IP)) {
		    return $customIP;
		}
		else {
		    return '$EXTERNAL_NET';
		}
	}

	public static function getIpPort($attribute) {
		$ipport = array();
		if (strpos($attribute['type'],'port') !== false) {
			$ipport = explode('|', $attribute['value']);
		} else {
		    $ipport[0] = $attribute['value'];
		    $ipport[1] = 'any';
		}		
		return $ipport;
	}
}
