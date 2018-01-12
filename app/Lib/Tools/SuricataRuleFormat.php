<?php

$rule = "drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:”ET TROJAN Likely Bot Nick in IRC (USA +..)”; flow:established,to_server; flowbits:isset,is_proto_irc; content:”NICK “; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; rev:2;)";

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

    function parseRule($rule) {
        $regexp = sprintf($this->rule_pattern, join('|', $this->actions));
        preg_match($regexp, $rule, $matches);
        return $matches;
    }
}