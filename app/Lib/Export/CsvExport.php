<?php

class CsvExport
{

    public $csv_event_context_fields_to_fetch = array(
        'event_info' => array('object' => false, 'var' => 'info'),
        'event_member_org' => array('object' => 'Org', 'var' => 'name'),
        'event_source_org' => array('object' => 'Orgc', 'var' => 'name'),
        'event_distribution' => array('object' => false, 'var' => 'distribution'),
        'event_threat_level_id' => array('object' => 'ThreatLevel', 'var' => 'name'),
        'event_analysis' => array('object' => false, 'var' => 'analysis'),
        'event_date' => array('object' => false, 'var' => 'date'),
        'event_tag' => array('object' => 'Tag', 'var' => 'name')
    );

    public function handler($attributes, $options = array())
    {
        $result = array();
        foreach ($attributes as $attribute) {
            $line1 = '';
            $line2 = '';
            foreach ($options['requested_attributes'] as $requested_attribute) {
                $line1 .= $attribute['Attribute'][$requested_attribute] . ',';
            }
            $line1 = rtrim($line1, ",");
            foreach ($options['requested_obj_attributes'] as $requested_obj_attribute) {
                $line2 .= $attribute['Object'][$requested_obj_attribute] . ',';
            }
            $line2 = rtrim($line2, ",");
            $line = $line1 . ',' . $line2;
            $line = rtrim($line, ",");
            if (!empty($options['includeContext'])) {
                foreach ($this->Event->csv_event_context_fields_to_fetch as $header => $field) {
                    if ($field['object']) {
                        $line .= ',' . $attribute['Event'][$field['object']][$field['var']];
                    } else {
                        $line .= ',' . str_replace(array("\n","\t","\r"), " ", $attribute['Event'][$field['var']]);
                    }
                }
            }
            $result[] = $line;
        }
        $result = implode(PHP_EOL, $result);
        return $result;
    }

    public function header($options = array())
    {
        if (!empty($options['requested_obj_attributes'])) {
            array_walk($options['requested_obj_attributes'], function (&$value, $key) {
                $value = 'object-'.$value;
            });
        }
        $headers = array_merge($options['requested_attributes'], $options['requested_obj_attributes']);
        if (!empty($options['includeContext'])) {
            $headers = array_merge($headers, array_keys($this->csv_event_context_fields_to_fetch));
        }
        foreach ($headers as $k => $v) {
            $headers[$k] = str_replace('-', '_', $v);
            if ($v == 'timestamp') {
                $headers[$k] = 'date';
            }
        }
        $headers = implode(',', $headers) . PHP_EOL;
        return $headers;
    }

    public function footer()
    {
        return PHP_EOL;
    }

    public function separator()
    {
        return PHP_EOL;
    }

}
