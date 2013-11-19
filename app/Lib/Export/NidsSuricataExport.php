<?php
App::uses('NidsExport', 'Export');

class NidsSuricataExport extends NidsExport {

	public function export($items, $startSid, $format = "suricata", $continue = false) {
		// set the specific format
		$this->format = "suricata";
		// call the generic function
		return parent::export($items, $startSid, $format, $continue);
	}

	// below overwrite functions from NidsExport
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
	    // warning: only suricata compatible
	    $content = 'flow:to_server,established; content: "Host|3a| ' . $attribute['value'] . '"; fast_pattern; nocase; http_header; pcre: "/[^A-Za-z0-9-\.]' . preg_quote($attribute['value']) . '[^A-Za-z0-9-\.]/H";';
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
	    // warning: only suricata compatible
	    $content = 'flow:to_server,established; content: "Host|3a|"; nocase; http_header; content:"' . $attribute['value'] . '"; fast_pattern; nocase; http_header; pcre: "/[^A-Za-z0-9-]' . preg_quote($attribute['value']) . '[^A-Za-z0-9-\.]/H";';
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
	            'tag:session,600,seconds;',		// tag
	            $sid,							// sid
	            1								// rev
	    );
	}

	public function urlRule($ruleFormat, $attribute, &$sid) {
	    // TODO in hindsight, an url should not be excluded given a host or domain name.
	    //$hostpart = parse_url($attribute['value'], PHP_URL_HOST);
	    //$overruled = $this->checkNames($hostpart);
	    // warning: only suricata compatible
	    $overruled = $this->checkWhitelist($attribute['value']);
	    $attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
	    $content = 'flow:to_server,established; content:"' . $attribute['value'] . '"; fast_pattern; nocase; http_uri;';
	    $this->rules[] = sprintf($ruleFormat,
	            ($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
	            'http',							// proto
	            '$HOME_NET',					// src_ip
	            'any',							// src_port
	            '->',							// direction
	            '$EXTERNAL_NET',				// dst_ip
	            'any',							// dst_port
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
	    // warning: only suricata compatible
	    $content = 'flow:to_server,established; content:"' . $attribute['value'] . '"; fast_pattern; http_user_agent;';
	    $this->rules[] = sprintf($ruleFormat,
	            ($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
	            'http',						// proto
	            '$HOME_NET',					// src_ip
	            'any',							// src_port
	            '->',							// direction
	            '$EXTERNAL_NET',				// dst_ip
	            'any',							// dst_port
	            'Outgoing User-Agent: ' . $attribute['value'],		// msg
	            $content,						// rule_content
	            'tag:session,600,seconds;',		// tag
	            $sid,							// sid
	            1								// rev
	    );
	}

}
