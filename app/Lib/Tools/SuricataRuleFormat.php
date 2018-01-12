<?php

# based on @jasonish idstools regexp
# https://github.com/jasonish/py-idstools/blob/master/idstools/rule.py

#$rule = "drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:”ET TROJAN Likely Bot Nick in IRC (USA +..)”; flow:established,to_server; flowbits:isset,is_proto_irc; content:”NICK “; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; rev:2;)";
#$rule = "drop  ->  (msg:”ET TROJAN Likely Bot Nick in IRC (USA +..)”; flow:established,to_server; flowbits:isset,is_proto_irc; content:”NICK “; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; rev:2;)";
#$rule = 'empty';

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

    private function findOptionEnd($option) {
        $offset = 0;
        while (true) {
            $i = strpos($option, ';');
            if ($i === false) {
                return -1;
            }
            if ($option[$offset + $i - 1] == '\\') {
                $offset += 2;
            }
            else {
                return $offset + 1;
            }
        }
    }

    function parseRule($rule) {
        $regexp = sprintf($this->rule_pattern, join('|', $this->actions));
        preg_match($regexp, $rule, $matches);
        return $matches;
    }

    # function to validate the global syntax of a suricata rule
    function validateRuleSyntax($rule) {
        $matches = $this->parseRule($rule);
        if (($matches == false) or ($matches['src_ip'] == false) or ($matches['dst_ip'] == false)) {
            return false;
        }
        return true;
    }

    #function to validate http rule mandatory arguments
    function validateRuleHTTP($rule) {
        // FIXME
        return true;
    }

    # function to validate dns rule mandatory arguments
    function validateRuleDNS($rule) {
        // FIXME
        return true;
    }

    # function to validate the complete syntax of a suricata rule
    # idea is to 
    function validateRule($rule) {
        return validateRuleSyntax($rule) and validateRuleHTTP($rule) and validateRuleDNS($rule);
    }
}