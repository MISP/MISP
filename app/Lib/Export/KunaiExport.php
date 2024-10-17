<?php

class KunaiExport
{
    public $additional_params = array(
        'flatten' => 1,
        'to_ids' => 1,
        'published' => 1,
        'type' => [
            'md5',
            'sha1',
            'sha256',
            'sha512',
            'domain',
            'hostname',
            'ip-dst',
            'domain|ip',
            'filename|md5',
            'malware-sample',
            'filename|sha1',
            'filename|sha256',
            'filename|sha512',
        ]
    );

    private $__source = null;

    private $__severity_base_scores = [
        'md5' => 10,
        'sha1' => 10,
        'sha256' => 10,
        'sha512' => 10,
        'domain' => 7,
        'hostname' => 7,
        'ip-dst' => 5
    ];

    private $__valid_types = [
        'md5',
        'sha1',
        'sha256',
        'sha512',
        'domain',
        'hostname',
        'ip-dst',
        'domain|ip',
        'filename|md5',
        'malware-sample',
        'filename|sha1',
        'filename|sha256',
        'filename|sha512',
    ];

    private $__type_mapping = array(
        'domain|ip' => [false, 'ip-dst'],
        'filename|md5' => [false, 'md5'],
        'malware-sample' => [false, 'md5'],
        'filename|sha1' => [false, 'sha1'],
        'filename|sha256' => [false, 'sha256'],
        'filename|sha512' => [false, 'sha512'],
    );

    private function __severity($attribute, $value, $type)
    {
        // Let's do more with this in the future
        $value = $this->__severity_base_scores[$type];
        return $value;
    }


    private function __convertAttribute($attribute, $event)
    {
        if (!in_array($attribute['type'], $this->__valid_types)) {
            return '';
        }
        if (isset($this->__type_mapping[$attribute['type']])) {
            $types_to_extract = $this->__type_mapping[$attribute['type']];
            $values = explode('|', $attribute['value']);
            foreach ($types_to_extract as $k => $type) {
                if ($type) {
                    $kunai_entry[] = json_encode([
                        "type" => $attribute['type'],
                        "uuid" => $attribute['uuid'],
                        "source" => $this->__source,
                        "value" => $values[$k],
                        "event_uuid" => $event['uuid'],
                        "severity" => $this->__severity($attribute, $values[$k], $type)
                    ]);
                }
            }
            return implode(', ', $kunai_entry);
        } else {
            $kunai_entry = json_encode([
                "type" => $attribute['type'],
                "uuid" => $attribute['uuid'],
                "source" => $this->__source,
                "value" => $attribute['value'],
                "event_uuid" => $event['uuid'],
                "severity" => $this->__severity($attribute, $attribute['value'], $attribute['type'])
            ]);
        }
        return $kunai_entry;
    }


    public function handler($data, $options = array())
    {
        $this->__source = sprintf(
            '[%s MISP] %s',
            Configure::read('MISP.org'),
            Configure::read('MISP.uuid')
        );
        if ($options['scope'] === 'Attribute') {
            return $this->__convertAttribute($data['Attribute'], $data['Event']);
        }
        if ($options['scope'] === 'Event') {
            $result = [];
            foreach ($data['Attribute'] as $attribute) {
                $temp = $this->__convertAttribute($attribute, $data['Event']);
                if ($temp) $result[] = $temp;
            }
            return $result;
        }
        return '';
    }

    public function header($options = array())
    {
        return '[';
    }

    public function footer()
    {
        return ']';
    }

    public function separator()
    {
        return ', ';
    }
}
