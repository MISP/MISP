<?php

/**
 * Exports IP attributes as an nfdump filter expression, so that the result can be
 * fed to nfdump directly in order to look up the matching netflow records:
 *
 *   nfdump -R /var/cache/nfdump -f misp_filter.txt
 *
 * By default the direction of every term is derived from the attribute type
 * (ip-src => "src host", ip-dst => "dst host"), types that carry no direction
 * (domain|ip) fall back to the undirected "host". The derived direction can be
 * overridden for the whole export with the nfdump_direction filter, which
 * accepts "src", "dst" or "any".
 */
class NfdumpExport
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

    /**
     * position: index of the IP inside a composite value, or 'full' if the whole value is the IP
     * direction: nfdump direction implied by the attribute type
     */
    private $__attributeTypeMappings = array(
        'ip-dst' => array('position' => 'full', 'direction' => 'dst'),
        'ip-src' => array('position' => 'full', 'direction' => 'src'),
        'domain|ip' => array('position' => 1, 'direction' => 'any'),
        'ip-dst|port' => array('position' => 0, 'direction' => 'dst'),
        'ip-src|port' => array('position' => 0, 'direction' => 'src')
    );

    public function handler($data, $options = array())
    {
        $direction = $this->__requestedDirection($options);
        if ($options['scope'] === 'Attribute') {
            return $this->__convertToFilter($data['Attribute'], $direction);
        }
        if ($options['scope'] === 'Event') {
            $result = array();
            foreach ($data['Attribute'] as $attribute) {
                $filter = $this->__convertToFilter($attribute, $direction);
                if ($filter !== '') {
                    $result[] = $filter;
                }
            }
            return implode($this->separator(), $result);
        }
        return '';
    }

    private function __requestedDirection($options)
    {
        if (empty($options['filters']['nfdump_direction'])) {
            return false;
        }
        $direction = $options['filters']['nfdump_direction'];
        return in_array($direction, array('src', 'dst', 'any'), true) ? $direction : false;
    }

    private function __convertToFilter($attribute, $direction)
    {
        if (!isset($this->__attributeTypeMappings[$attribute['type']])) {
            return '';
        }
        $mapping = $this->__attributeTypeMappings[$attribute['type']];
        if ($mapping['position'] === 'full') {
            $value = $attribute['value'];
        } else {
            $parts = explode('|', $attribute['value']);
            if (!isset($parts[$mapping['position']])) {
                return '';
            }
            $value = $parts[$mapping['position']];
        }
        if ($direction === false) {
            $direction = $mapping['direction'];
        }
        $prefix = $direction === 'any' ? '' : $direction . ' ';
        if (strpos($value, '/') !== false) {
            list($network, $mask) = explode('/', $value, 2);
            if (filter_var($network, FILTER_VALIDATE_IP) === false || !ctype_digit($mask)) {
                return '';
            }
            return sprintf('%snet %s/%s', $prefix, $network, $mask);
        }
        if (filter_var($value, FILTER_VALIDATE_IP) === false) {
            return '';
        }
        return sprintf('%shost %s', $prefix, $value);
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
        return " or ";
    }
}
