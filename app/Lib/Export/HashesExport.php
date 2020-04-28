<?php

class HashesExport
{
    public $additional_params = array(
        'flatten' => 1
    );

    public $validTypes = array(
        'simple' => array(
            'md5', 'sha1', 'sha256', 'sha224', 'sha512', 'sha512/224', 'sha512/256', 'ssdeep', 'imphash', 'tlsh',
            'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'pehash', 'authentihash',
            'impfuzzy'
        ),
        'composite' => array(
            'malware-sample', 'filename|md5', 'filename|sha1', 'filename|sha256', 'filename|sha224', 'filename|sha512',
            'filename|sha512/224', 'filename|sha512/256', 'filename|ssdeep', 'filename|imphash', 'filename|tlsh',
            'x509-fingerprint-sha1', 'x509-fingerprint-md5', 'x509-fingerprint-sha256', 'filename|pehash',
            'filename|authentihash', 'filename|impfuzzy'
        )
    );

    public function handler($data, $options = array())
    {
        if ($options['scope'] === 'Attribute') {
            if (in_array($data['Attribute']['type'], $this->validTypes['composite'])) {
                return explode('|', $data['Attribute']['value'])[1];
            } else if (in_array($data['Attribute']['type'], $this->validTypes['simple'])) {
                return $data['Attribute']['value'];
            }
        }
        if ($options['scope'] === 'Event') {
            $result = array();
            foreach ($data['Attribute'] as $attribute) {
                if (in_array($attribute['type'], $this->validTypes['composite'])) {
                    $result[] = explode('|', $attribute['value'])[1];
                } else if (in_array($attribute['type'], $this->validTypes['simple'])) {
                    $result[] = $attribute['value'];
                }
            }
            return implode($this->separator(), $result);
        }
        return '';
    }

    public function header($options = array())
    {
        return '';
    }

    public function footer()
    {
        return "\n";
    }

    public function separator()
    {
        return "\n";
    }
}
