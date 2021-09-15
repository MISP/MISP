<?php
App::uses('NidsExport', 'Export');

class NidsSuricataExport extends NidsExport
{
    public function export($items, $startSid, $format = "suricata", $continue = false)
    {
        // set the specific format
        $this->format = "suricata";
        // call the generic function
        return parent::export($items, $startSid, $format, $continue);
    }

    // below overwrite functions from NidsExport
    public function hostnameRule($ruleFormat, $attribute, &$sid)
    {
        $overruled = $this->checkWhitelist($attribute['value']);
        $attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
        $content = 'dns.query; content:"'.$attribute['value'].'"; nocase; pcre: "/(^|[^A-Za-z0-9-\.])' . preg_quote($attribute['value']) . '$/i";';
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
        // warning: only suricata compatible
        $content = 'flow:to_server,established; http.header; content: "Host|3a| ' . $attribute['value'] . '"; fast_pattern; nocase; pcre: "/(^|[^A-Za-z0-9-\.])' . preg_quote($attribute['value']) . '[^A-Za-z0-9-\.]/Hi";';
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
    }

    public function domainRule($ruleFormat, $attribute, &$sid)
    {
        $overruled = $this->checkWhitelist($attribute['value']);
        $attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
        $content = 'dns.query; content:"'.$attribute['value'].'"; nocase; pcre: "/(^|[^A-Za-z0-9-])' . preg_quote($attribute['value']) . '$/i";';
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
        // warning: only suricata compatible
        $content = 'flow:to_server,established; http.header; content: "Host|3a|"; nocase; http.header; content:"' . $attribute['value'] . '"; fast_pattern; nocase; pcre: "/(^|[^A-Za-z0-9-])' . preg_quote($attribute['value']) . '[^A-Za-z0-9-\.]/Hi";';
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
    }

    public function urlRule($ruleFormat, $attribute, &$sid)
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
                $content = 'tls.sni; content:"' . $data['host'] . '";';
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
                # Cannot create a satisfaisant rule (user could create a domain attribute if needed)
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
                # Cannot create a satisfaisant rule (user could create a domain attribute if needed)
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

    public function userAgentRule($ruleFormat, $attribute, &$sid)
    {
        $overruled = $this->checkWhitelist($attribute['value']);
        $attribute['value'] = NidsExport::replaceIllegalChars($attribute['value']);  // substitute chars not allowed in rule
        // warning: only suricata compatible
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

    public function ja3Rule($ruleFormat, $attribute, &$sid)
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
    public function ja3sRule($ruleFormat, $attribute, &$sid)
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
