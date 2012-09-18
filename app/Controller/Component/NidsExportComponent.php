<?php

class NidsExportComponent extends Component {

    public $rules = array();
    public $classtype = 'trojan-activity';

    function explain() {
        $this->rules[] = '# These NIDS rules contain some variables that need to exist in your configuration.';
        $this->rules[] = '# Make sure you have set:';
        $this->rules[] = '#';
        $this->rules[] = '# $HOME_NET     - Your internal network range';
        $this->rules[] = '# $EXTERNAL_NET - The network considered as outside';
        $this->rules[] = '# $SMTP_SERVERS - All your internal SMTP servers';
        $this->rules[] = '# $HTTP_PORTS   - The ports used to contain HTTP traffic (not required with suricata export)';
        $this->rules[] = '# ';
    }

    function suricataRules($items, $start_sid) {
		$this->whitelist = $this->populateWhitelist();

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
            $rule_format_msg = 'msg: "CyDefSIG e'.$item['Event']['id'].' %s"';
            $rule_format_reference = 'reference:url,'.Configure::read('CyDefSIG.baseurl').'/events/view/'.$item['Event']['id'];
            $rule_format = '%salert %s %s %s %s %s %s ('.$rule_format_msg.'; %s %s classtype:'.$this->classtype.'; sid:%d; rev:%d; priority:'.$priority.'; '.$rule_format_reference.';) ';

            $sid = $start_sid+($item['Attribute']['id']*10);  // leave 9 possible rules per attribute type
            $attribute = &$item['Attribute'];

            $sid++;
            switch ($attribute['type']) {
                // LATER nids - test all the snort attributes
                // LATER nids - add the tag keyword in the rules to capture network traffic
                // LATER nids - sanitize every $attribute['value'] to not conflict with snort
                case 'ip-dst':
                    $this->ipDstRule($rule_format, $attribute, $sid);
                    break;
                case 'ip-src':
                    $this->ipSrcRule($rule_format, $attribute, $sid);
                    break;
                case 'email-src':
                    $this->emailSrcRule($rule_format, $attribute, $sid);
                    break;
                case 'email-dst':
                    $this->emailDstRule($rule_format, $attribute, $sid);
                    break;
                case 'email-subject':
                    $this->emailSubjectRule($rule_format, $attribute, $sid);
                    break;
                case 'email-attachment':
                    $this->emailAttachmentRule($rule_format, $attribute, $sid);
                    break;
                case 'domain':
                    $this->domainRule($rule_format, $attribute, $sid);
                    break;
                case 'hostname':
                    $this->hostnameRule($rule_format, $attribute, $sid);
                    break;
                case 'url':
                    $this->urlRule($rule_format, $attribute, $sid);
                    break;
                case 'user-agent':
                    $this->userAgentRule($rule_format, $attribute, $sid);
                    break;
                case 'snort':
                    $this->snortRule($rule_format, $attribute, $sid, $rule_format_msg, $rule_format_reference);
                default:
                    break;


            }

        }



		return $this->rules;


    }

    function ipDstRule($rule_format, $attribute, &$sid) {
    	$overruled = in_array($attribute['value'], $this->whitelist);
        $this->rules[] = sprintf($rule_format,
        		($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
                'ip',                           // proto
                '$HOME_NET',                    // src_ip
                'any',                          // src_port
                '->',                           // direction
                $attribute['value'],            // dst_ip
                'any',                          // dst_port
                'Outgoing To IP: '.$attribute['value'],           // msg
                '',                             // rule_content
                '',                             // tag
                $sid,                           // sid
                1                               // rev
                );

    }

    function ipSrcRule($rule_format, $attribute, &$sid) {
    	$overruled = in_array($attribute['value'], $this->whitelist);
    	$this->rules[] = sprintf($rule_format,
        		($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
                'ip',                           // proto
                $attribute['value'],            // src_ip
                'any',                          // src_port
                '->',                           // direction
                '$HOME_NET',                    // dst_ip
                'any',                          // dst_port
                'Incoming From IP: '.$attribute['value'],         // msg
                '',                             // rule_content
                '',                             // tag
                $sid,                           // sid
                1                               // rev
                );
    }

    function emailSrcRule($rule_format, $attribute, &$sid) {
    	$content = 'flow:established,to_server; content:"MAIL FROM|3a|"; nocase; content:"'.$attribute['value'].'"; nocase;';
        $this->rules[] = sprintf($rule_format,
        		(false) ? '#OVERRULED BY WHITELIST# ' : '',
                'tcp',                          // proto
                '$EXTERNAL_NET',                // src_ip
                'any',                          // src_port
                '<>',                           // direction
                '$SMTP_SERVERS',                // dst_ip
                '25',                           // dst_port
                'Source Email Address: '.$attribute['value'],     // msg
                $content,                       // rule_content
                'tag:session,600,seconds;',     // tag
                $sid,                           // sid
                1                               // rev
                );
    }

    function emailDstRule($rule_format, $attribute, &$sid) {
    	$content = 'flow:established,to_server; content:"RCPT TO|3a|"; nocase; content:"'.$attribute['value'].'"; nocase;';
        $this->rules[] = sprintf($rule_format,
        		(false) ? '#OVERRULED BY WHITELIST# ' : '',
                'tcp',                          // proto
                '$EXTERNAL_NET',                // src_ip
                'any',                          // src_port
                '<>',                           // direction
                '$SMTP_SERVERS',                // dst_ip
                '25',                           // dst_port
                'Destination Email Address: '.$attribute['value'],// msg
                $content,                       // rule_content
                'tag:session,600,seconds;',     // tag
                $sid,                           // sid
                1                               // rev
                );
    }

    function emailSubjectRule($rule_format, $attribute, &$sid) {
    	// LATER nids - email-subject rule might not match because of line-wrapping
        $content = 'flow:established,to_server; content:"Subject|3a|"; nocase; content:"'.$attribute['value'].'"; nocase;';
        $this->rules[] = sprintf($rule_format,
        		(false) ? '#OVERRULED BY WHITELIST# ' : '',
                'tcp',                          // proto
                '$EXTERNAL_NET',                // src_ip
                'any',                          // src_port
                '<>',                           // direction
                '$SMTP_SERVERS',                // dst_ip
                '25',                           // dst_port
                'Bad Email Subject',            // msg
                $content,                       // rule_content
                'tag:session,600,seconds;',     // tag
                $sid,                           // sid
                1                               // rev
                );
    }

    function emailAttachmentRule($rule_format, $attribute, &$sid) {
    	// LATER nids - email-attachment rule might not match because of line-wrapping
        $content = 'flow:established,to_server; content:"Content-Disposition: attachment|3b| filename=|22|"; content:"'.$attribute['value'].'|22|";';
        $this->rules[] = sprintf($rule_format,
        		(false) ? '#OVERRULED BY WHITELIST# ' : '',
                'tcp',                          // proto
                '$EXTERNAL_NET',                // src_ip
                'any',                          // src_port
                '<>',                           // direction
                '$SMTP_SERVERS',                // dst_ip
                '25',                           // dst_port
                'Bad Email Attachment',         // msg
                $content,                       // rule_content   // LATER nids - test and finetune this snort rule https://secure.wikimedia.org/wikipedia/en/wiki/MIME#Content-Disposition
                'tag:session,600,seconds;',     // tag
                $sid,                           // sid
                1                               // rev
                );
    }

    function hostnameRule($rule_format, $attribute, &$sid) {
    	$overruled = $this->checkNames($attribute['value']);
    	$content = 'content:"'.$this->dnsNameToRawFormat($attribute['value'], 'hostname').'"; nocase;';
        $this->rules[] = sprintf($rule_format,
        		($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
                'udp',                          // proto
                'any',                          // src_ip
                'any',                          // src_port
                '->',                           // direction
                'any',                          // dst_ip
                '53',                           // dst_port
                'Hostname: '.$attribute['value'],         // msg
                $content,                       // rule_content
                '',                             // tag
                $sid,                           // sid
                1                               // rev
        );
        $sid++;
        $this->rules[] = sprintf($rule_format,
        		($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
                'tcp',                          // proto
                'any',                          // src_ip
                'any',                          // src_port
                '->',                           // direction
                'any',                          // dst_ip
                '53',                           // dst_port
                'Hostname: '.$attribute['value'],         // msg
                $content,                       // rule_content
                '',                             // tag
                $sid,                           // sid
                1                               // rev
        );
        $sid++;
        // also do http requests
        // warning: only suricata compatible
        $content = 'flow:to_server,established; content: "Host: '.$attribute['value'].'"; nocase; http_header; pcre: "/[^A-Za-z0-9-]'.preg_quote($attribute['value']).'[^A-Za-z0-9-]/";';
        $this->rules[] = sprintf($rule_format,
			($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
                'http',                         // proto
                '$HOME_NET',                    // src_ip
                'any',                          // src_port
                '->',                           // direction
                '$EXTERNAL_NET',                // dst_ip
                'any',                          // dst_port
                'Outgoing HTTP Hostname: '.$attribute['value'],        // msg
                $content,                       // rule_content
                'tag:session,600,seconds;',     // tag
                $sid,                           // sid
                1                               // rev
        );
    }

    function domainRule($rule_format, $attribute, &$sid) {
    	$overruled = $this->checkNames($attribute['value']);
       	$content = 'content:"'.$this->dnsNameToRawFormat($attribute['value']).'"; nocase;';
        $this->rules[] = sprintf($rule_format,
        		($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
                'udp',                          // proto
                'any',                          // src_ip
                'any',                          // src_port
                '->',                           // direction
                'any',                          // dst_ip
                '53',                           // dst_port
                'Domain: '.$attribute['value'],         // msg
                $content,                       // rule_content
                '',                             // tag
                $sid,                           // sid
                1                               // rev
                );
        $sid++;
        $this->rules[] = sprintf($rule_format,
        		($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
                'tcp',                          // proto
                'any',                          // src_ip
                'any',                          // src_port
                '->',                           // direction
                'any',                          // dst_ip
                '53',                           // dst_port
                'Domain: '.$attribute['value'],         // msg
                $content,                       // rule_content
                '',                             // tag
                $sid,                           // sid
                1                               // rev
                );
        $sid++;
        // also do http requests,
        // warning: only suricata compatible
        $content = 'flow:to_server,established; content: "Host:"; nocase; http_header; content:"'.$attribute['value'].'"; nocase; http_header; pcre: "/[^A-Za-z0-9-]'.preg_quote($attribute['value']).'[^A-Za-z0-9-]/";';
        $this->rules[] = sprintf($rule_format,
			($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
                'http',                         // proto
                '$HOME_NET',                    // src_ip
                'any',                          // src_port
                '->',                           // direction
                '$EXTERNAL_NET',                // dst_ip
                'any',                          // dst_port
                'Outgoing HTTP Domain: '.$attribute['value'],        // msg
                $content,                       // rule_content
                'tag:session,600,seconds;',     // tag
                $sid,                           // sid
                1                               // rev
        );
    }

    function urlRule($rule_format, $attribute, &$sid) {
    	// TODO in hindsight, an url should not be excluded given a host or domain name.
//    	$hostpart = parse_url($attribute['value'], PHP_URL_HOST);
//    	$overruled = $this->checkNames($hostpart);
    	// warning: only suricata compatible
        $content = 'flow:to_server,established; content:"'.$attribute['value'].'"; nocase; http_uri;';
        $this->rules[] = sprintf($rule_format,
        		(false) ? '#OVERRULED BY WHITELIST# ' : '',
                'http',                          // proto
                '$HOME_NET',                    // src_ip
                'any',                          // src_port
                '->',                           // direction
                '$EXTERNAL_NET',                // dst_ip
                'any',                          // dst_port
                'Outgoing HTTP URL: '.$attribute['value'],        // msg
                $content,                       // rule_content
                'tag:session,600,seconds;',     // tag
                $sid,                           // sid
                1                               // rev
                );
    }

    function userAgentRule($rule_format, $attribute, &$sid) {
        // TODO nids - write snort user-agent rule

    }

    function snortRule($rule_format, $attribute, &$sid, $rule_format_msg, $rule_format_reference) {
        // LATER nids - test using lots of snort rules.
        $tmp_rule = $attribute['value'];

        // rebuild the rule by overwriting the different keywords using preg_replace()
        //   sid       - '/sid\s*:\s*[0-9]+\s*;/'
        //   rev       - '/rev\s*:\s*[0-9]+\s*;/'
        //   classtype - '/classtype:[a-zA-Z_-]+;/'
        //   msg       - '/msg\s*:\s*".*?"\s*;/'
        //   reference - '/reference\s*:\s*.+?;/'
        //   tag       - '/tag\s*:\s*.+?;/'
        $replace_count=array();
        $tmp_rule = preg_replace('/sid\s*:\s*[0-9]+\s*;/', 'sid:'.$sid.';', $tmp_rule, -1, $replace_count['sid']);
        if (null == $tmp_rule ) break;  // don't output the rule on error with the regex
        $tmp_rule = preg_replace('/rev\s*:\s*[0-9]+\s*;/', 'rev:1;', $tmp_rule, -1, $replace_count['rev']);
        if (null == $tmp_rule ) break;  // don't output the rule on error with the regex
        $tmp_rule = preg_replace('/classtype:[a-zA-Z_-]+;/', 'classtype:'.$this->classtype.';', $tmp_rule, -1, $replace_count['classtype']);
        if (null == $tmp_rule ) break;  // don't output the rule on error with the regex
        $tmp_message = sprintf($rule_format_msg, 'snort-rule');
        $tmp_rule = preg_replace('/msg\s*:\s*".*?"\s*;/', $tmp_message.';', $tmp_rule, -1, $replace_count['msg']);
        if (null == $tmp_rule ) break;  // don't output the rule on error with the regex
        $tmp_rule = preg_replace('/reference\s*:\s*.+?;/', $rule_format_reference.';', $tmp_rule, -1, $replace_count['reference']);
        if (null == $tmp_rule ) break;  // don't output the rule on error with the regex
        $tmp_rule = preg_replace('/reference\s*:\s*.+?;/', $rule_format_reference.';', $tmp_rule, -1, $replace_count['reference']);
        if (null == $tmp_rule ) break;  // don't output the rule on error with the regex
        // FIXME nids -  implement priority overwriting

        // some values were not replaced, so we need to add them ourselves, and insert them in the rule
        $extra_for_rule="";
        if (0 == $replace_count['sid']) {
            $extra_for_rule .= 'sid:'.$sid.';';
        } if (0 == $replace_count['rev']) {
            $extra_for_rule .= 'rev:1;';
        } if (0 == $replace_count['classtype']) {
            $extra_for_rule .= 'classtype:'.$this->classtype.';';
        } if (0 == $replace_count['msg']) {
            $extra_for_rule .= $tmp_message.';';
        } if (0 == $replace_count['reference']) {
            $extra_for_rule .= $rule_format_reference.';';
        }
        $tmp_rule = preg_replace('/;\s*\)/', '; '.$extra_for_rule.')', $tmp_rule);

        // finally the rule is cleaned up and can be outputed
        $this->rules[] = $tmp_rule;


    }

    /**
     * Converts a DNS name to a raw format usable in NIDS like Snort.
     *   example host: foobar.com becomes |00||06|foobar|03|com|00|
     *   example domain: foobar.com becomes |06|foobar|03|com|00|
     * @param string $name dns name to be converted
     * @param string $type the type of dns name - domain (default) or hostname
     * @return string raw snort compatible format of the dns name
     */
    function dnsNameToRawFormat($name, $type='domain') {
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
            if (1 == strlen($hexLength)) $hexLength = '0'.$hexLength;
            $rawName .= '|'.$hexLength.'|'.$explodedName;
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
    function dnsNameToMSDNSLogFormat($name) {
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
            $rawName .= '('.$hexLength.')'.$explodedName;
        }
        // put all together
        $rawName .= '(0)';
        // and append |00| to terminate the name
        return $rawName;
    }

    public $whitelist = array();

    function populateWhitelist() {
    	$whitelistCheck = array();

		$this->Whitelist = ClassRegistry::init('Whitelist');
        $whitelist = $this->Whitelist->find('all', array('recursive' => 0,'fields' => 'name'));

    	// loop through whitelist table,
    	foreach ($whitelist as $whitelistItem) {
    		$ipl = array();
    		$ipl[] = $whitelistItem['Whitelist']['name'];
    		$whitelistCheck = array_merge($whitelistCheck,$ipl);
    		if (count($ipl) > 0 && $whitelistItem != $ipl[0]) {
	    		$dummyArray = array();
	    		$dummyArray[] = $whitelistItem['Whitelist']['name'];
	    		$whitelistCheck = array_merge($whitelistCheck,$dummyArray);
    		}
    	}
    	return $whitelistCheck;
    }

    function checkNames($name) {
    	// FIXME fix the checkNames() function and concept
    	$ipl = array();
    	$ipl[] = $name;
    	$overruled = false;
    	foreach ($ipl as $ip) {
    		$overruled = in_array($ip, $this->whitelist);
    		if ($overruled) break;
    	}
        return $overruled;
    }
}
