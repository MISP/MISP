<?php

class NetfilterExport
{
    public $additional_params = array(
        'flatten' => 1,
        'conditions' => array(
            'AND' => array(
                'Attribute.type' => array(
                    'ip-dst', 'ip-src', 'domain|ip', 'ip-dst|port', 'ip-src|port'
                )
            )
        )
    );

    public $non_restrictive_export = true;

    private $__attributeTypeMappings = array(
        'ip-dst' => 'full',
        'ip-src' => 'full',
        'domain|ip' => 1,
        'ip-dst|port' => 0,
        'ip-src|port' => 0
    );

    private const ALLOWED_ACTIONS = array('DROP', 'REJECT', 'ACCEPT', 'LOG');

    public function handler($data, $options = array())
    {
        $action = 'DROP';
        if (
            !empty($options['filters']['netfilter_action']) &&
            is_string($options['filters']['netfilter_action']) &&
            in_array($options['filters']['netfilter_action'], self::ALLOWED_ACTIONS, true)
        ) {
            $action = $options['filters']['netfilter_action'];
        }
        if ($options['scope'] === 'Attribute') {
            if (in_array($data['Attribute']['type'], array_keys($this->__attributeTypeMappings))) {
                return $this->__convertToRule($data['Attribute'], $action) . "\n";
            } else {
                return '';
            }
        }
        if ($options['scope'] === 'Event') {
            $result = array();
            foreach ($data['Attribute'] as $attribute) {
                if (isset($this->__attributeTypeMappings[$attribute['type']])) {
                    $result[] = $this->__convertToRule($attribute, $action) . "\n";
                }
            }
            return implode($this->separator(), $result);
        }
        return '';
    }

    private function __convertToRule($attribute, $action)
    {
        $ip = false;
        if ($this->__attributeTypeMappings[$attribute['type']] === 'full') {
            $ip = $attribute['value'];
        } else {
            $ip = explode('|', $attribute['value']);
            $ip = $ip[$this->__attributeTypeMappings[$attribute['type']]];
        }
        return sprintf(
            'iptables -A INPUT -s %s -j %s',
            $ip,
            $action
        );
    }

    public function header($options = array())
    {
        return '';
    }

    public function footer()
    {
        return "";
    }

    public function separator()
    {
        return "";
    }
}
