<?php
App::uses('NidsExport', 'Export');

class NidsSuricataExport extends NidsExport
{
    protected $format = "suricata";

    protected function export($items, $startSid)
    {
        // generate the rules
        foreach ($items as $item) {
            // retrieve all tags for this item to add them to the msg
            $tagsArray = [];
            if (!empty($item['AttributeTag'])) {
                foreach ($item['AttributeTag'] as $tag_attr) {
                    if (array_key_exists('name', $tag_attr['Tag'])) {
                        $tagsArray[] = $tag_attr['Tag']['name'];
                    }
                }
            }
            if (!empty($item['Event']['EventTag'])) {
                foreach ($item['Event']['EventTag'] as $tag_event) {
                    if (array_key_exists('name', $tag_event['Tag'])) {
                        $tagsArray[] = $tag_event['Tag']['name'];
                    }
                }
            }
            $ruleFormatMsgTags = implode(",", $tagsArray);

            # proto src_ip src_port direction dst_ip dst_port msg rule_content tag sid rev
            // $ruleFormatMsg = 'msg: "MISP e' . $item['Event']['id'] . ' [' . $ruleFormatMsgTags . '] %s"';
            // Replaced with references
            $ruleFormatMsg = 'msg: "MISP e' . $item['Event']['id'] . ' %s"';
            $ruleMeta = $this->convertTagsToMeta($tagsArray);
            $ruleMeta[] = 'misp_event_uuid ' . $item['Event']['uuid'];
            $ruleMeta[] = 'misp_ioc ' . str_replace(' ', '_', $item['Attribute']['value']);
            $ruleMeta[] = 'created_at ' . date('Y_m_d', $item['Attribute']['timestamp']);
            $ruleMeta[] = 'updated_at ' . date('Y_m_d', time());
            $ruleMeta = implode(',', $ruleMeta);
            $ruleMeta = str_replace('%', '%%', $ruleMeta); // escape % for sprintf
            $ruleType = 'alert';
            $ruleFormatReference = 'reference:url,' . Configure::read('MISP.baseurl') . '/events/view/' . $item['Event']['id'];
            $ruleFormat = '%s' . $ruleType . ' %s %s %s %s %s %s (' . $ruleFormatMsg . '; %s %s classtype:' . $this->classtype . '; sid:%d; rev:%d; priority:' . $item['Event']['threat_level_id'] . '; ' . $ruleFormatReference . '; metadata:' . $ruleMeta . ';)';

            $sid = $startSid + ($item['Attribute']['id'] * 10); // leave 9 possible rules per attribute type
            $sid++;

            if (!empty($item['Attribute']['type'])) { // item is an 'Attribute'
                switch ($item['Attribute']['type']) {
                    // LATER nids - test all the snort attributes
                    // LATER nids - add the tag keyword in the rules to capture network traffic
                    // LATER nids - sanitize every $attribute['value'] to not conflict with snort
                    case 'ip-dst':
                    case 'ip-dst|port':
                        $this->ipDstRule($ruleFormat, $item['Attribute'], $sid);
                        break;
                    case 'ip-src':
                    case 'ip-src|port':
                        $this->ipSrcRule($ruleFormat, $item['Attribute'], $sid);
                        break;
                    case 'email':
                        $this->emailSrcRule($ruleFormat, $item['Attribute'], $sid);
			            $sid++;
                        $this->emailDstRule($ruleFormat, $item['Attribute'], $sid);
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
                    case 'email-x-mailer':
                        $this->emailSimpleRule($ruleFormat, $item['Attribute'], $sid);
                        break;
                    case 'email-message-id':
                        $this->emailSimpleRule($ruleFormat, $item['Attribute'], $sid);
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
                    case 'ja3-fingerprint-md5':
                        $this->ja3Rule($ruleFormat, $item['Attribute'], $sid);
                        break;
                    case 'ja3s-fingerprint-md5': // Attribute type doesn't exists yet (2020-12-10) but ready when created.
                        $this->ja3sRule($ruleFormat, $item['Attribute'], $sid);
                        break;
                    case 'snort':
                        $this->snortRule($item['Attribute'], $sid, $ruleFormatMsg, $ruleFormatReference);
                        // no break
                    case 'filename':
                    case 'filename|md5':
                    case 'filename|sha1':
                    case 'filename|sha256':
                    case 'md5':
                    case 'sha1':
                    case 'sha256':
                    case 'malware-sample':
                        $this->fileRule($ruleFormat, $item['Attribute'], $sid);
                        break;
                    case 'pattern-in-file':
                        $this->patternInFileRule($ruleFormat, $item['Attribute'], $sid);
                        break;
                    case 'filename-pattern':
                        $this->filenamePatternRule($ruleFormat, $item['Attribute'], $sid);
                        break;
                    case 'cookie':
                        $this->cookieRule($ruleFormat, $item['Attribute'], $sid);
                        break;
                    default:
                        break;
                }

            } else if (!empty($item['Attribute']['name'])) { // Item is an 'Object'

                switch ($item['Attribute']['name']) {
                    case 'network-connection':
                        $this->networkConnectionRule($ruleFormat, $item['Attribute'], $sid);
                        break;
                    case 'ddos':
                        $this->ddosRule($ruleFormat, $item['Attribute'], $sid);
                        break;
                    default:
                        break;
                }
            }
        }
    }


    protected function convertTagsToMeta($tagsArray)
    {
        $results = [];
        foreach ($tagsArray as $tag) {
            $temp = explode(':', $tag);
            if (count($temp) == 1) {
                $result = 'misp-tag ' . str_replace(' ', '_', $tag);
            } else {
                $namespace = $temp[0];
                $temp2 = explode('=', $temp[1]);
                if (count($temp2) == 1) {
                    $result = $namespace . ' ' . str_replace(' ', '_', $temp[1]);
                } else {
                    if ($namespace == 'misp-galaxy' && $temp2[0] == 'mitre-attack-pattern') {
                        preg_match('#T[0-9]{1,4}(\.[0-9]{0,3})?#', $temp2[1], $matches);
                        if (!empty($matches)) {
                            $results[] = 'mitre_tactic_id ' . $matches[0];
                        }
                    }
                    $result = $namespace . ':' . $temp2[0] . ' ' . str_replace(' ', '_', trim($temp2[1], '"'));
                }
            }
            $results[] = $result;
        }
        return $results;
    }

    protected function cookieRule($ruleFormat, $attribute, $sid)
    {
        $attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
        $content = 'http.cookie; content:"' . $attribute['value'] . '"; nocase;';
        $this->rules[] = sprintf(
            $ruleFormat,
                '',
                'http',						// proto
                '$HOME_NET',					// src_ip
                'any',							// src_port
                '->',							// direction
                '$EXTERNAL_NET',				// dst_ip
                'any',							// dst_port
                'Cookie ' . $attribute['value'],		// msg
                $content,						// rule_content
                'tag:session,600,seconds;',		// tag
                $sid,							// sid
                1								// rev
        );
    }

    protected function emailSimpleRule($ruleFormat, $attribute, $sid)
    {
        $attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
        $typeLookup = [
            'email-x-mailer' => 'email.x_mailer',
            'email-message-id' => 'email.message_id' 
        ];
        $nameLookup = [
            'email-x-mailer' => 'Email X-mailer',
            'email-message-id' => 'Email Message-ID' 
        ];
        $requirements = [
            'email-x-mailer' => 'requires: version>=8.0.0; ',
            'email-message-id' => ''
        ];
        $content = $typeLookup[$attribute['type']] . '; ' . $requirements[$attribute['type']] . 'content:"' . $attribute['value'] . '"; nocase;';
        $this->rules[] = sprintf(
            $ruleFormat,
                '',
                'tcp',						// proto
                'any',					// src_ip
                'any',							// src_port
                '->',							// direction
                'any',				// dst_ip
                'any',							// dst_port
                $nameLookup['type'] . ' ' . $attribute['value'],		// msg
                $content,						// rule_content
                '',								// tag
                $sid,							// sid
                1								// rev
        );
    }

    protected function patternInFileRule($ruleFormat, $attribute, &$sid)
    {
        $attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
        $content = 'file.data; pcre:\"/' . $attribute['value'] . '/\";';
        $this->rules[] = sprintf(
            $ruleFormat,
                '',
                'tcp',						// proto
                'any',					// src_ip
                'any',							// src_port
                '->',							// direction
                'any',				// dst_ip
                'any',							// dst_port
                'Pattern in File ' . $attribute['value'],		// msg
                $content,						// rule_content
                '',								// tag
                $sid,							// sid
                1								// rev
        );
    }

    protected function filenamePatternRule($ruleFormat, $attribute, &$sid)
    {
        $attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
        $content = 'file.name; pcre:\"/' . $attribute['value'] . '/\";';
        $this->rules[] = sprintf(
            $ruleFormat,
                '',
                'tcp',						// proto
                'any',					// src_ip
                'any',							// src_port
                '->',							// direction
                'any',				// dst_ip
                'any',							// dst_port
                'Filename Pattern ' . $attribute['value'],		// msg
                $content,						// rule_content
                '',								// tag
                $sid,							// sid
                1								// rev
        );
    }

    protected function fileRule($ruleFormat, $attribute, &$sid)
    {
        $compositeTypes = ['filename|md5', 'filename|sha1', 'filename|sha256', 'malware-sample'];
        $filenameIoc = null;
        $hashIoc = null;
        if (in_array($attribute['type'], $compositeTypes)) {
            $hashIoc = $attribute;
            $hashIoc['value'] = explode('|', $attribute['value'])[1];
            $type = explode('|', $attribute['type']);
            if (count($type) > 1) {
                $hashIoc['type'] = $type[1];
            } else {
                $hashIoc['type'] = 'md5';
            }
        } else {
            if ($attribute['type'] === 'filename') {
                $filenameIoc = $attribute;
            } else {
                $hashIoc = $attribute;
            }
        }
        if (!empty($filenameIoc)) {
            $filenameIoc['value'] = NidsExport::replaceIllegalChars($filenameIoc['value']);  // substitute chars not allowed in rule
            $content = 'content:"' . $filenameIoc['value'] . '"; startswith; endswith;';
            $this->rules[] = sprintf(
                $ruleFormat,
                    '',
                    'tcp',						// proto
                    'any',					// src_ip
                    'any',							// src_port
                    '->',							// direction
                    'any',				// dst_ip
                    'any',							// dst_port
                    'Filename ' . $filenameIoc['value'],		// msg
                    $content,						// rule_content
                    '',								// tag
                    $sid,							// sid
                    1								// rev
            );
            if (!empty($hashIoc)) $sid++;
        }
        /*
        Not implemented yet in Suricata
        if (!empty($hashIoc)) {
            $hashIoc['value'] = NidsExport::replaceIllegalChars($hashIoc['value']);  // substitute chars not allowed in rule
            $content = 'to_' . $hashIoc['type'] . '; content:"' . $hashIoc['value'] . '"; startswith; endswith;';
            $this->rules[] = sprintf(
                $ruleFormat,
                    '',
                    'tcp',						// proto
                    'any',					// src_ip
                    'any',							// src_port
                    '->',							// direction
                    'any',				// dst_ip
                    'any',							// dst_port
                    'File Hash ' . $hashIoc['value'],		// msg
                    $content,						// rule_content
                    '',								// tag
                    $sid,							// sid
                    1								// rev
            );
        }
        */
    }

    // below overwrite functions from NidsExport
    protected function hostnameRule($ruleFormat, $attribute, &$sid)
    {
        $overruled = $this->checkWhitelist($attribute['value']);
        $attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
        $content = 'dns.query; content:"' . $attribute['value'] . '"; startswith; endswith;';
        $this->rules[] = sprintf(
            $ruleFormat,
                ($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
                'dns',							// proto
                'any',							// src_ip
                'any',							// src_port
                '->',							// direction
                'any',							// dst_ip
                'any',							// dst_port
                'Hostname ' . $attribute['value'],		// msg
                $content,						// rule_content
                '',								// tag
                $sid,							// sid
                1								// rev
        );
        $sid++;
        // also do http requests
        $content = 'flow:to_server,established; http.host; content:"' . $attribute['value'] . '"; startswith; endswith;';
        $this->rules[] = sprintf(
            $ruleFormat,
                ($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
                'http',						// proto
                '$HOME_NET',					// src_ip
                'any',							// src_port
                '->',							// direction
                '$EXTERNAL_NET',				// dst_ip
                'any',							// dst_port
                'Outgoing HTTP Hostname ' . $attribute['value'],		// msg
                $content,						// rule_content
                'tag:session,600,seconds;',		// tag
                $sid,							// sid
                1								// rev
        );
        // also do https requests
        $sid++;
        $content = 'flow:to_server,established; tls.sni; content:"' . $attribute['value'] . '"; startswith; endswith;';
        $this->rules[] = sprintf(
            $ruleFormat,
                ($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
                'tls',						// proto
                '$HOME_NET',					// src_ip
                'any',							// src_port
                '->',							// direction
                '$EXTERNAL_NET',				// dst_ip
                'any',							// dst_port
                'Outgoing HTTPS Hostname ' . $attribute['value'],		// msg
                $content,						// rule_content
                'tag:session,600,seconds;',		// tag
                $sid,							// sid
                1								// rev
        );
    }

    protected function domainRule($ruleFormat, $attribute, &$sid)
    {
        $overruled = $this->checkWhitelist($attribute['value']);
        $attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
        $content = 'dns.query; content:"' . $attribute['value'] . '"; startswith; endswith;';
        $this->rules[] = sprintf(
            $ruleFormat,
                ($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
                'dns',							// proto
                'any',							// src_ip
                'any',							// src_port
                '->',							// direction
                'any',							// dst_ip
                'any',							// dst_port
                'Domain ' . $attribute['value'],		// msg
                $content,						// rule_content
                '',								// tag
                $sid,							// sid
                1								// rev
        );
        $sid++;
        // also do http requests,
        $content = 'flow:to_server,established; http.host; content:"' . $attribute['value'] . '"; startswith; endswith;';
        $this->rules[] = sprintf(
            $ruleFormat,
                ($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
                'http',						// proto
                '$HOME_NET',					// src_ip
                'any',							// src_port
                '->',							// direction
                '$EXTERNAL_NET',				// dst_ip
                'any',							// dst_port
                'Outgoing HTTP Domain ' . $attribute['value'],		// msg
                $content,						// rule_content
                'tag:session,600,seconds;',		// tag
                $sid,							// sid
                1								// rev
        );
        // also do https requests
        $sid++;
        $content = 'flow:to_server,established; tls.sni; content:"' . $attribute['value'] . '"; startswith; endswith;';
        $this->rules[] = sprintf(
            $ruleFormat,
                ($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
                'tls',						// proto
                '$HOME_NET',					// src_ip
                'any',							// src_port
                '->',							// direction
                '$EXTERNAL_NET',				// dst_ip
                'any',							// dst_port
                'Outgoing HTTPS Domain ' . $attribute['value'],		// msg
                $content,						// rule_content
                'tag:session,600,seconds;',		// tag
                $sid,							// sid
                1								// rev
        );
    }

    protected function urlRule($ruleFormat, $attribute, &$sid)
    {
        $createRule = true;
        $overruled = $this->checkWhitelist($attribute['value']);

        $scheme = parse_url($attribute['value'], PHP_URL_SCHEME);
        $data = parse_url($attribute['value']);
        if (is_array($data)) {
            if (!array_key_exists('port', $data)) {
                $data['port'] = null;
            }
            if (!array_key_exists('host', $data)) {
                $data['host'] = '';
            }
        }
        switch ($scheme) {
            case "http":
                $data['host'] = NidsExport::replaceIllegalChars($data['host']);
                $data['host'] = trim($data['host'], '[]');
                $suricata_protocol = 'http';
                $suricata_src_ip = '$HOME_NET';
                $suricata_src_port = 'any';
                $suricata_dst_ip = NidsExport::getCustomIP($data['host']);
                $suricata_dst_port = NidsExport::getProtocolPort($scheme, $data['port']);
                $tag = 'tag:session,600,seconds;';
                if (!array_key_exists('path', $data)) {
                    $data['path'] = NidsExport::replaceIllegalChars($data['host']);
                    $content = 'flow:to_server,established; http.header; content:"' . $data['host'] . '"; nocase;';
                } else {
                    $content = 'flow:to_server,established; http.header; content:"' . $data['host'] . '"; fast_pattern; nocase; http.uri; content:"' . $data['path'] . '"; nocase;';
                }
                break;

            case "https":
                $data['host'] = NidsExport::replaceIllegalChars($data['host']);
                $tag = 'tag:session,600,seconds;';
                # IP: classic IP rule for HTTPS
                $suricata_protocol = 'tls';
                $suricata_src_ip = '$HOME_NET';
                $suricata_src_port = 'any';
                $suricata_dst_ip = '$EXTERNAL_NET';
                $suricata_dst_port = NidsExport::getProtocolPort($scheme, $data['port']);
                if (!array_key_exists('path', $data)) {
                    $data['path'] = NidsExport::replaceIllegalChars($data['host']);
                    $content = 'tls.sni; content:"' . $data['host'] . '"; nocase;';
                } else {
                    $createRule = false;
                }
                break;

            case "ssh":
                # IP: classic IP rule for SSH
                if (filter_var($data['host'], FILTER_VALIDATE_IP)) {
                    $suricata_protocol = 'tcp';
                    $suricata_src_ip = '$HOME_NET';
                    $suricata_src_port = 'any';
                    $suricata_dst_ip = $data['host'];
                    $suricata_dst_port = '$SSH_PORTS';
                    $content = 'flow:to_server; app-layer-protocol:ssh;';
                    $tag = '';
                }
                # Cannot create a satisfying rule (user could create a domain attribute if needed)
                else {
                    $createRule = false;
                }
                break;

            case "ftp":
                # IP: classic IP rule for FTP
                if (filter_var($data['host'], FILTER_VALIDATE_IP)) {
                    $suricata_protocol = 'tcp';
                    $suricata_src_ip = '$HOME_NET';
                    $suricata_src_port = 'any';
                    $suricata_dst_ip = $data['host'];
                    $suricata_dst_port = NidsExport::getProtocolPort($scheme, $data['port']);
                    $content = 'flow:to_server; app-layer-protocol:ftp;';
                    $tag = '';
                }
                # Cannot create a satisfying rule (user could create a domain attribute if needed)
                else {
                    $createRule = false;
                }
                break;

            # Unknown/No protocol: keep old behaviour
            default:
                $suricata_protocol = 'http';
                $suricata_src_ip = '$HOME_NET';
                $suricata_src_port = 'any';
                $suricata_dst_ip = '$EXTERNAL_NET';
                $suricata_dst_port = 'any';

                $url = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
                $content = 'flow:to_server,established; http.uri; content:"' . $url . '"; fast_pattern; nocase;';
                $tag = 'tag:session,600,seconds;';

                break;
        }
        if ($createRule) {
            $attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
            $this->rules[] = sprintf(
                $ruleFormat,
                ($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
                $suricata_protocol, // proto
                $suricata_src_ip,			// src_ip
                $suricata_src_port,			// src_port
                '->',						// direction
                $suricata_dst_ip,			// dst_ip
                $suricata_dst_port,			// dst_port
                'Outgoing URL ' . $attribute['value'],		// msg
                $content,					// rule_content
                $tag,						// tag
                $sid,						// sid
                1							// rev
            );
        }
    }

    protected function userAgentRule($ruleFormat, $attribute, &$sid)
    {
        $overruled = $this->checkWhitelist($attribute['value']);
        $attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
        $content = 'flow:to_server,established; content:"' . $attribute['value'] . '"; fast_pattern; http_user_agent;';
        $this->rules[] = sprintf(
            $ruleFormat,
                ($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
                'http',						// proto
                '$HOME_NET',					// src_ip
                'any',							// src_port
                '->',							// direction
                '$EXTERNAL_NET',				// dst_ip
                'any',							// dst_port
                'Outgoing User-Agent ' . $attribute['value'],		// msg
                $content,						// rule_content
                'tag:session,600,seconds;',		// tag
                $sid,							// sid
                1								// rev
        );
    }

    protected function ja3Rule($ruleFormat, $attribute, &$sid)
    {
        $overruled = $this->checkWhitelist($attribute['value']);
        $attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
        $content = 'ja3.hash; content:"' . $attribute['value'] . '"; fast_pattern;';
        $this->rules[] = sprintf(
            $ruleFormat,
                ($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
                'tls',						// proto
                'any',					// src_ip
                'any',							// src_port
                '->',							// direction
                'any',				// dst_ip
                'any',					// dst_port
                'JA3 Hash: ' . $attribute['value'],		// msg
                $content,						// rule_content
                'tag:session,600,seconds;',		// tag
                $sid,							// sid
                1								// rev
        );
    }

    // For Future use once JA3S Hash Attribute type is created
    protected function ja3sRule($ruleFormat, $attribute, &$sid)
    {
        $overruled = $this->checkWhitelist($attribute['value']);
        $attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
        $content = 'ja3s.hash; content:"' . $attribute['value'] . '"; fast_pattern;';
        $this->rules[] = sprintf(
            $ruleFormat,
                ($overruled) ? '#OVERRULED BY WHITELIST# ' : '',
                'tls',						// proto
                'any',					// src_ip
                'any',							// src_port
                '->',							// direction
                'any',				// dst_ip
                'any',					// dst_port
                'JA3S Hash: ' . $attribute['value'],		// msg
                $content,						// rule_content
                'tag:session,600,seconds;',		// tag
                $sid,							// sid
                1								// rev
        );
    }
}
