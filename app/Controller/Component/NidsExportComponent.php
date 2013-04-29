<?php

class NidsExportComponent extends Component {

	public $rules = array();

	public $classtype = 'trojan-activity';

	public function explain() {
		$this->rules[] = '# These NIDS rules contain some variables that need to exist in your configuration.';
		$this->rules[] = '# Make sure you have set:';
		$this->rules[] = '#';
		$this->rules[] = '# $HOME_NET	 - Your internal network range';
		$this->rules[] = '# $EXTERNAL_NET - The network considered as outside';
		$this->rules[] = '# $SMTP_SERVERS - All your internal SMTP servers';
		$this->rules[] = '# $HTTP_PORTS   - The ports used to contain HTTP traffic (not required with suricata export)';
		$this->rules[] = '# ';
	}

	public function export($items, $startSid) {
		$this->Whitelist = ClassRegistry::init('Whitelist');
		$this->whitelist = $this->Whitelist->populateWhitelist();

		$this->explain();

		foreach ($items as &$item) {
			switch ($item['Event']['risk']) {
				case 'Undefined':
					$priority = '4';
					break;
				case 'Low':
					$priority = '3';
					break;
				case 'Medium':
					$priority = '2';
					break;
				case 'High':
					$priority = '1';
					break;
				default:
					$priority = '4';
			}

			# proto src_ip src_port direction dst_ip dst_port msg rule_content tag sid rev
			$ruleFormatMsg = 'msg: "' . Configure::read('CyDefSIG.name') . ' e' . $item['Event']['id'] . ' %s"';
			$ruleFormatReference = 'reference:url,' . Configure::read('CyDefSIG.baseurl') . '/events/view/' . $item['Event']['id'];
			$ruleFormat = '%salert %s %s %s %s %s %s (' . $ruleFormatMsg . '; %s %s classtype:' . $this->classtype . '; sid:%d; rev:%d; priority:' . $priority . '; ' . $ruleFormatReference . ';) ';

			$sid = $startSid + ($item['Attribute']['id'] * 10); // leave 9 possible rules per attribute type
			$attribute = &$item['Attribute'];

			$sid++;
			switch ($attribute['type']) {
				// LATER nids - test all the snort attributes
				// LATER nids - add the tag keyword in the rules to capture network traffic
				// LATER nids - sanitize every $attribute['value'] to not conflict with snort
				case 'ip-dst':
					$this->ipDstRule($ruleFormat, $attribute, $sid);
					break;
				case 'ip-src':
					$this->ipSrcRule($ruleFormat, $attribute, $sid);
					break;
				case 'email-src':
					$this->emailSrcRule($ruleFormat, $attribute, $sid);
					break;
				case 'email-dst':
					$this->emailDstRule($ruleFormat, $attribute, $sid);
					break;
				case 'email-subject':
					$this->emailSubjectRule($ruleFormat, $attribute, $sid);
					break;
				case 'email-attachment':
					$this->emailAttachmentRule($ruleFormat, $attribute, $sid);
					break;
				case 'domain':
					$this->domainRule($ruleFormat, $attribute, $sid);
					break;
				case 'hostname':
					$this->hostnameRule($ruleFormat, $attribute, $sid);
					break;
				case 'url':
					$this->urlRule($ruleFormat, $attribute, $sid);
					break;
				case 'user-agent':
					$this->userAgentRule($ruleFormat, $attribute, $sid);
					break;
				case 'snort':
					$this->snortRule($ruleFormat, $attribute, $sid, $ruleFormatMsg, $ruleFormatReference);
				default:
					break;
			}

		}

		return $this->rules;
	}

	public function ipDstRule($ruleFormat, $attribute, &$sid) {
		$overruled = in_array($attribute['value'], $this->whitelist);
		$this->rules[] = sprintf($ruleFormat,
				($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
				'ip',							// proto
				'$HOME_NET',					// src_ip
				'any',							// src_port
				'->',							// direction
				$attribute['value'],			// dst_ip
				'any',							// dst_port
				'Outgoing To IP: ' . $attribute['value'],		// msg
				'',							// rule_content
				'',							// tag
				$sid,							// sid
				1								// rev
				);
	}

	public function ipSrcRule($ruleFormat, $attribute, &$sid) {
		$overruled = in_array($attribute['value'], $this->whitelist);
		$this->rules[] = sprintf($ruleFormat,
				($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
				'ip',							// proto
				$attribute['value'],			// src_ip
				'any',							// src_port
				'->',							// direction
				'$HOME_NET',					// dst_ip
				'any',							// dst_port
				'Incoming From IP: ' . $attribute['value'],		// msg
				'',							// rule_content
				'',							// tag
				$sid,							// sid
				1								// rev
				);
	}

	public function emailSrcRule($ruleFormat, $attribute, &$sid) {
		$content = 'flow:established,to_server; content:"MAIL FROM|3a|"; nocase; content:"' . $attribute['value'] . '"; nocase;';
		$this->rules[] = sprintf($ruleFormat,
				(false) ? '#OVERRULED BY WHITELIST# ' : '',
				'tcp',							// proto
				'$EXTERNAL_NET',				// src_ip
				'any',							// src_port
				'<>',							// direction
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
		$content = 'flow:established,to_server; content:"RCPT TO|3a|"; nocase; content:"' . $attribute['value'] . '"; nocase;';
		$this->rules[] = sprintf($ruleFormat,
				(false) ? '#OVERRULED BY WHITELIST# ' : '',
				'tcp',							// proto
				'$EXTERNAL_NET',				// src_ip
				'any',							// src_port
				'<>',							// direction
				'$SMTP_SERVERS',				// dst_ip
				'25',							// dst_port
				'Destination Email Address: ' . $attribute['value'],	// msg
				$content,						// rule_content
				'tag:session,600,seconds;',	// tag
				$sid,							// sid
				1								// rev
				);
	}

	public function emailSubjectRule($ruleFormat, $attribute, &$sid) {
		// LATER nids - email-subject rule might not match because of line-wrapping
		$content = 'flow:established,to_server; content:"Subject|3a|"; nocase; content:"' . $attribute['value'] . '"; nocase;';
		$this->rules[] = sprintf($ruleFormat,
				(false) ? '#OVERRULED BY WHITELIST# ' : '',
				'tcp',							// proto
				'$EXTERNAL_NET',				// src_ip
				'any',							// src_port
				'<>',							// direction
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
		$content = 'flow:established,to_server; content:"Content-Disposition: attachment|3b| filename=|22|"; content:"' . $attribute['value'] . '|22|";';
		$this->rules[] = sprintf($ruleFormat,
				(false) ? '#OVERRULED BY WHITELIST# ' : '',
				'tcp',							// proto
				'$EXTERNAL_NET',				// src_ip
				'any',							// src_port
				'<>',							// direction
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
		$overruled = in_array($attribute['value'], $this->whitelist);
		$content = 'content:"' . $this->dnsNameToRawFormat($attribute['value'], 'hostname') . '"; nocase;';
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
				'',							// tag
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
				$content,						// rule_content
				'',							// tag
				$sid,							// sid
				1								// rev
		);
		$sid++;
		// also do http requests
		// warning: only suricata compatible
		$content = 'flow:to_server,established; content: "Host: ' . $attribute['value'] . '"; nocase; http_header; pcre: "/[^A-Za-z0-9-]' . preg_quote($attribute['value']) . '[^A-Za-z0-9-]/";';
		$this->rules[] = sprintf($ruleFormat,
			($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
				'http',						// proto
				'$HOME_NET',					// src_ip
				'any',							// src_port
				'->',							// direction
				'$EXTERNAL_NET',				// dst_ip
				'any',							// dst_port
				'Outgoing HTTP Hostname: ' . $attribute['value'],		// msg
				$content,						// rule_content
				'tag:session,600,seconds;',	// tag
				$sid,							// sid
				1								// rev
		);
	}

	public function domainRule($ruleFormat, $attribute, &$sid) {
		$overruled = in_array($attribute['value'], $this->whitelist);
		$content = 'content:"' . $this->dnsNameToRawFormat($attribute['value']) . '"; nocase;';
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
				'',							// tag
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
				$content,						// rule_content
				'',							// tag
				$sid,							// sid
				1								// rev
				);
		$sid++;
		// also do http requests,
		// warning: only suricata compatible
		$content = 'flow:to_server,established; content: "Host:"; nocase; http_header; content:"' . $attribute['value'] . '"; nocase; http_header; pcre: "/[^A-Za-z0-9-]' . preg_quote($attribute['value']) . '[^A-Za-z0-9-]/";';
		$this->rules[] = sprintf($ruleFormat,
			($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
				'http',						// proto
				'$HOME_NET',					// src_ip
				'any',							// src_port
				'->',							// direction
				'$EXTERNAL_NET',				// dst_ip
				'any',							// dst_port
				'Outgoing HTTP Domain: ' . $attribute['value'],		// msg
				$content,						// rule_content
				'tag:session,600,seconds;',	// tag
				$sid,							// sid
				1								// rev
		);
	}

	public function urlRule($ruleFormat, $attribute, &$sid) {
		// TODO in hindsight, an url should not be excluded given a host or domain name.
		//$hostpart = parse_url($attribute['value'], PHP_URL_HOST);
		//$overruled = $this->checkNames($hostpart);
		// warning: only suricata compatible
		$content = 'flow:to_server,established; content:"' . $attribute['value'] . '"; nocase; http_uri;';
		$this->rules[] = sprintf($ruleFormat,
				(false) ? '#OVERRULED BY WHITELIST# ' : '',
				'http',							// proto
				'$HOME_NET',					// src_ip
				'any',							// src_port
				'->',							// direction
				'$EXTERNAL_NET',				// dst_ip
				'any',							// dst_port
				'Outgoing HTTP URL: ' . $attribute['value'],		// msg
				$content,						// rule_content
				'tag:session,600,seconds;',	// tag
				$sid,							// sid
				1								// rev
				);
	}

	public function userAgentRule($ruleFormat, $attribute, &$sid) {
		// TODO nids - write snort user-agent rule
	}

	public function snortRule($ruleFormat, $attribute, &$sid, $ruleFormatMsg, $ruleFormatReference) {
		// LATER nids - test using lots of snort rules.
		$tmpRule = $attribute['value'];

		// rebuild the rule by overwriting the different keywords using preg_replace()
		//   sid	   - '/sid\s*:\s*[0-9]+\s*;/'
		//   rev	   - '/rev\s*:\s*[0-9]+\s*;/'
		//   classtype - '/classtype:[a-zA-Z_-]+;/'
		//   msg	   - '/msg\s*:\s*".*?"\s*;/'
		//   reference - '/reference\s*:\s*.+?;/'
		//   tag	   - '/tag\s*:\s*.+?;/'
		$replaceCount = array();
		$tmpRule = preg_replace('/sid\s*:\s*[0-9]+\s*;/', 'sid:' . $sid . ';', $tmpRule, -1, $replaceCount['sid']);
		if (null == $tmpRule ) break;	// don't output the rule on error with the regex
		$tmpRule = preg_replace('/rev\s*:\s*[0-9]+\s*;/', 'rev:1;', $tmpRule, -1, $replaceCount['rev']);
		if (null == $tmpRule ) break;	// don't output the rule on error with the regex
		$tmpRule = preg_replace('/classtype:[a-zA-Z_-]+;/', 'classtype:' . $this->classtype . ';', $tmpRule, -1, $replaceCount['classtype']);
		if (null == $tmpRule ) break;	// don't output the rule on error with the regex
		$tmpMessage = sprintf($ruleFormatMsg, 'snort-rule');
		$tmpRule = preg_replace('/msg\s*:\s*".*?"\s*;/', $tmpMessage . ';', $tmpRule, -1, $replaceCount['msg']);
		if (null == $tmpRule ) break;	// don't output the rule on error with the regex
		$tmpRule = preg_replace('/reference\s*:\s*.+?;/', $ruleFormatReference . ';', $tmpRule, -1, $replaceCount['reference']);
		if (null == $tmpRule ) break;	// don't output the rule on error with the regex
		$tmpRule = preg_replace('/reference\s*:\s*.+?;/', $ruleFormatReference . ';', $tmpRule, -1, $replaceCount['reference']);
		if (null == $tmpRule ) break;	// don't output the rule on error with the regex
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
	}

/**
 * Converts a DNS name to a raw format usable in NIDS like Snort.
 *   example host: foobar.com becomes |00||06|foobar|03|com|00|
 *   example domain: foobar.com becomes |06|foobar|03|com|00|
 * @param string $name dns name to be converted
 * @param string $type the type of dns name - domain (default) or hostname
 * @return string raw snort compatible format of the dns name
 */
	public function dnsNameToRawFormat($name, $type='domain') {
		$rawName = "";
		if ('hostname' == $type) $rawName = '|00|';
		// explode using the dot
		$explodedNames = explode('.', $name);
		// for each part
		foreach ($explodedNames as &$explodedName) {
			// count the lenght of the part, and add |length| before
			$length = strlen($explodedName);
			if ($length > 255) exit('ERROR: dns name is to long for RFC'); // LATER log correctly without dying
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
	public function dnsNameToMSDNSLogFormat($name) {
		$rawName = "";
		// in MS DNS log format we can't use (0) to distinguish between hostname and domain (including subdomains)
		// explode using the dot
		$explodedNames = explode('.', $name);
		// for each part
		foreach ($explodedNames as &$explodedName) {
			// count the lenght of the part, and add |length| before
			$length = strlen($explodedName);
			if ($length > 255) exit('ERROR: dns name is to long for RFC'); // LATER log correctly without dying
			$hexLength = dechex($length);
			$rawName .= '(' . $hexLength . ')' . $explodedName;
		}
		// put all together
		$rawName .= '(0)';
		// and append |00| to terminate the name
		return $rawName;
	}
}
