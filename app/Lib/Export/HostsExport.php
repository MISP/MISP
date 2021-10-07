<?php

class HostsExport
{
    public $additional_params = [
        'flatten' => 1,
        'conditions' => [
            'AND' => [
                'Attribute.type' => [
                    'domain'
                ]
            ]
        ]
    ];

    private $default_ip_address = '0.0.0.0';
    private $addedDomain = [];

    public $non_restrictive_export = false;

    public function handler($data, $options = array())
    {
        if ($options['scope'] === 'Attribute') {
            if ($this->isNewDomain($data['Attribute'])) {
                return $this->__convertToRule($data['Attribute']) . "\n";
            }
        }
        if ($options['scope'] === 'Event') {
            $result = array();
            foreach ($data['Attribute'] as $attribute) {
                if ($this->isNewDomain($data['Attribute'])) {
                    $result[] = $this->__convertToRule($data['Attribute']);
                }
            }
            return implode($this->separator(), $result) . "\n";
        }
        return '';
    }

    private function __convertToRule($attribute)
    {
        return "{$this->ip_address} {$attribute['value']}";
    }

    private function isNewDomain($attribute)
    {
        if (empty($this->addedDomain[$attribute['value']])) {
            $this->addedDomain[$attribute['value']] = true;
            return true;
        }
        return false;
    }

    public function header($options = array())
    {
        $this->ip_address = !empty($options['filters']['ip_address']) ? $options['filters']['ip_address'] : $this->default_ip_address;
        $header = "# Blocklist in the HOSTS format\n";
        $header .= sprintf("# Generated: %s\n", date("Y-m-d H:i:s O"));
        return $header;
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
