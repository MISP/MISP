<?php

# based on @jasonish idstools regexp
# https://github.com/jasonish/py-idstools/blob/master/idstools/rule.py

#$rule = 'drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)"; flow:established,to_server; flowbits:isset,is_proto_irc; content:"NICK "; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; rev:2;)';
#$rule = 'drop  ->  (msg:"ET TROJAN Likely Bot Nick in IRC (USA +..)"; flow:established,to_server; flowbits:isset,is_proto_irc; content:"NICK "; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; rev:2;)';
#$rule = 'empty';
$rule = 'alert dns any any -> any any (msg:"Test dns_query option"; dns_query; content:"google"; nocase; sid:1;)';

class SuricataRuleFormat {
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

    private function findOptionEnd($options) {
        $offset = 0;
        while (true) {
            $i = strpos($options, ';', $offset);
            if ($i === false) {
                return -1;
            }
            if ($options[$offset + $i - 1] == '\\') {
                $offset += 2;
            }
            else {
                return $offset + $i;
            }
        }
    }

    private function getOptions($options) {
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
            if ($delim == false) {
                $name = $option;
                $value = None;
            }
            else {
                $vals = explode(':', $option);
                $name = $vals[0];
                $value = $vals[1];
            }
            $name = str_replace(' ', '', $name);
            $opt_list[$name] = $value;
        }
        return $opt_list;
    }

    private function parseRule($rule) {
        $regexp = sprintf($this->rule_pattern, join('|', $this->actions));
        preg_match($regexp, $rule, $matches);
        return $matches;
    }

    # function to validate the global syntax of a suricata rule
    private function validateRuleSyntax($rule) {
        $matches = $this->parseRule($rule);
        if (($matches == false) or ($matches['src_ip'] == false) or ($matches['dst_ip'] == false)) {
            return false;
        }
        return true;
    }

    #function to validate http rule keywords order (sticky vs modifiers)
    private function validateRuleHTTP($rule) {
        // FIXME
        return true;
    }

    # function to validate dns rule keywords order
    private function validateRuleDNS($rule) {
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
        if ($keys[$dns_query + 1] != 'content') {
            return false;
        }
        print_r($options);
        return true;
    }

    # function to validate the complete syntax of a suricata rule
    # idea is to 
    public function validateRule($rule) {
        return $this->validateRuleSyntax($rule) and $this->validateRuleHTTP($rule) and $this->validateRuleDNS($rule);
    }
}