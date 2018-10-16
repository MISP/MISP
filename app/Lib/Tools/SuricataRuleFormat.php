<?php

# based on @jasonish idstools regexp
# https://github.com/jasonish/py-idstools/blob/master/idstools/rule.py

class SuricataRuleFormat
{
    private $actions = array("alert", "log", "pass", "activate", "dynamic", "drop", "reject", "sdrop");
    private $rule_pattern = '/(?P<action>%s)\s*'
                            . '(?P<protocol>[^\s]*)\s*'
                            . '(?P<src_ip>[^\s]*)\s*'
                            . '(?P<src_port>[^\s]*)\s*'
                            . '(?P<direction>->|<>)\s*'
                            . '(?P<dst_ip>[^\s]*)\s*'
                            . '(?P<dst_port>[^\s]*)\s*'
                            . '\((?P<options>.*)\)\s*'
                            . '/';
    private $http_req_modifiers = array('http_uri', 'http_raw_uri', 'http_method', 'http_client_body', 'http_header', 'http_raw_header', 'http_cookie', 'http_user_agent', 'http_host', 'http_raw_host');
    private $http_req_sticky = array('http_request_line', 'http_accept', 'http_accept_lang', 'http_accept_enc', 'http_referer', 'http_connection', 'http_content_type', 'http_content_len', 'http_start', 'http_protocol', 'http_header_names');
    private $http_res_modifiers = array('http_stat_msg', 'http_stat_code', 'http_header', 'http_raw_header', 'http_cookie', 'http_server_body');
    private $http_res_sticky = array('http_response_line', 'file_data', 'http_content_type', 'http_content_len', 'http_start', 'http_protocol', 'http_header_names');

    private function findOptionEnd($options)
    {
        $offset = 0;
        while (true) {
            $i = strpos($options, ';', $offset);
            if ($i === false) {
                return -1;
            }
            if ($options[$offset + $i - 1] == '\\') {
                $offset += 2;
            } else {
                return $offset + $i;
            }
        }
    }

    private function getOptions($options)
    {
        $opt_list = array();

        if ($options == false) {
            return false;
        }
        while (true) {
            if ($options == false) {
                return $opt_list;
            }
            $index = $this->findOptionEnd($options);
            if ($index < 0) {
                throw new LogicException(
                    'SuricataRule - could not find end of options'
                );
            }
            $option = substr($options, 0, $index);
            $options = substr($options, $index + 1);
            $delim = strpos($option, ':');
            if ($delim === false) {
                $name = $option;
                $value = None;
            } else {
                $vals = explode(':', $option);
                $name = $vals[0];
                $value = $vals[1];
            }
            $name = str_replace(' ', '', $name);
            $opt_list[$name] = $value;
        }
        return $opt_list;
    }

    private function parseRule($rule)
    {
        $regexp = sprintf($this->rule_pattern, join('|', $this->actions));
        preg_match($regexp, $rule, $matches);
        return $matches;
    }

    # function to validate the global syntax of a suricata rule
    private function validateRuleSyntax($rule)
    {
        $matches = $this->parseRule($rule);
        if (($matches === false) or ($matches['src_ip'] === false) or ($matches['dst_ip'] === false)) {
            return false;
        }
        return true;
    }

    #function to validate http rule keywords order (sticky vs modifiers)
    private function validateRuleHTTP($rule)
    {
        $matches = $this->parseRule($rule);
        if ($matches['protocol'] != 'http') {
            return true;
        }
        $options = $this->getOptions($matches['options']);
        $keys = array_keys($options);
        foreach ($keys as $k) {
            if (in_array($k, $this->http_req_modifiers) or in_array($k, $this->http_res_modifiers)) {
                $mod = array_search($k, $keys);
                if (($mod != 0) and ($keys[$mod - 1] != 'content')) {
                    return false;
                }
            } elseif (in_array($k, $this->http_req_sticky) or in_array($k, $this->http_res_sticky)) {
                $mod = array_search($k, $keys);
                if (($mod != (count($keys) - 1)) and ($keys[$mod + 1] != 'content')) {
                    return false;
                }
            }
        }
        return true;
    }

    # function to validate dns rule keywords order
    private function validateRuleDNS($rule)
    {
        $matches = $this->parseRule($rule);
        if ($matches['protocol'] != 'dns') {
            return true;
        }
        $options = $this->getOptions($matches['options']);
        $keys = array_keys($options);
        $dns_query = array_search('dns_query', $keys);
        if ($dns_query == false) {
            return true;
        }
        if (($dns_query != (count($keys) - 1)) and ($keys[$dns_query + 1] != 'content')) {
            return false;
        }
        return true;
    }

    # function to validate the complete syntax of a suricata rule
    # idea is to
    public function validateRule($rule)
    {
        return $this->validateRuleSyntax($rule) and $this->validateRuleHTTP($rule) and $this->validateRuleDNS($rule);
    }
}
