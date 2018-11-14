<?php

class RPZExport
{
    private $__policies = array(
            'walled-garden' => array(
                    'explanation' => 'returns the defined alternate location.',
                    'action' => '$walled_garden',
                    'setting_id' => 3,
            ),
            'NXDOMAIN' => array(
                    'explanation' => 'return NXDOMAIN (name does not exist) irrespective of actual result received.',
                    'action' => '.',
                    'setting_id' => 1,
            ),
            'NODATA' => array(
                    'explanation' => 'returns NODATA (name exists but no answers returned) irrespective of actual result received.',
                    'action' => '*.',
                    'setting_id' => 2,
            ),
            'DROP' => array(
                    'explanation' => 'timeout.',
                    'action' => 'rpz-drop.',
                    'setting_id' => 0,
            ),
    );

	private $__items = array();

	public $additional_params = array(
		'flatten' => 1
	);

	private $__rpzSettings = array();

	private $__valid_policies = array('NXDOMAIN', 'NODATA', 'DROP', 'walled-garden');

	private $__server = null;

	public $validTypes = array(
		'ip-src' => array(
				'value' => 'ip'
		),
		'ip-dst' => array(
				'value' => 'ip'
		),
		'domain' => array(
				'value' => 'domain'
		),
		'domain|ip' => array(
				'value1' => 'domain',
				'value2' => 'ip'
		),
		'hostname' => array(
				'value' => 'hostname'
		)
	);

	public function handler($data, $options = array())
	{
		if ($options['scope'] === 'Attribute') {
			return $this->__attributeHandler($data, $options);
		} else {
			return $this->__eventHandler($data, $options);
		}
	}

	private function __eventHandler($event, $options = array()) {
		foreach ($event['Attribute'] as $attribute) {
			if (isset($this->validTypes[$attribute['type']])) {
				if ($attribute['type'] == 'domain|ip') {
					$temp = explode('|', $attribute['value']);
					$attribute['value1'] = $temp[0];
					$attribute['value2'] = $temp[1];
				}
				$this->__attributeHandler(array('Attribute' => $attribute, $options));
			}
		}
		return '';
	}

	private function __attributeHandler($attribute, $options = array())
	{
		if (isset($attribute['Attribute'])) {
			$attribute = $attribute['Attribute'];
		}
		if (isset($this->validTypes[$attribute['type']])) {
			foreach ($this->validTypes[$attribute['type']] as $field => $mapping) {
				// get rid of the in_array check
				if (empty($this->__items[$mapping]) || !isset($this->__items[$mapping][$attribute[$field]])) {
					$this->__items[$mapping][$attribute[$field]] = true;
				}
			}
		}
		return '';
	}

	public function header($options = array())
	{
		$lookupData = array('policy', 'walled_garden', 'ns', 'ns_alt', 'email', 'serial', 'refresh', 'retry', 'expiry', 'minimum_ttl', 'ttl');
		foreach ($lookupData as $v) {
			if ($v === 'policy' && isset($options['filters'][$v])) {
				if (!in_array($options['filters'][$v], array('NXDOMAIN', 'NODATA', 'DROP', 'walled-garden'))) {
					unset($options['filters'][$v]);
				} else {
					$options['filters'][$v] = $this->getIdByPolicy($options['filters'][$v]);
				}
			}
			if (isset($options['filters'][$v])) {
				$this->__rpzSettings[$v] = $options['filters'][$v];
			} else {
				$tempSetting = Configure::read('Plugin.RPZ_' . $v);
				if (isset($tempSetting)) {
					$this->__rpzSettings[$v] = Configure::read('Plugin.RPZ_' . $v);
				} else {
					if (empty($this->__server)) {
						$this->__server = ClassRegistry::init('Server');
					}
					$this->__rpzSettings[$v] = $this->__server->serverSettings['Plugin']['RPZ_' . $v]['value'];
				}
			}
		}
		return '';
	}

	public function footer($options = array())
	{
		foreach ($this->__items as $k => $v) {
			$this->__items[$k] = array_keys($this->__items[$k]);
		}
		return $this->export($this->__items, $this->__rpzSettings);
	}

	public function separator()
	{
		return '';
	}

    public function getPolicyById($id)
    {
        foreach ($this->__policies as $k => $v) {
            if ($id == $v['setting_id']) {
                return $k;
            }
        }
    }

    public function getIdByPolicy($policy)
    {
        return $this->__policies[$policy]['setting_id'];
    }

    public function explain($type, $policy)
    {
        $explanations = array(
            'ip' => '; The following list of IP addresses will ',
            'domain' => '; The following domain names and all of their sub-domains will ',
            'hostname' => '; The following hostnames will '
        );
        $policy_explanations = array(
            'walled-garden' => 'returns the defined alternate location.',
            'NXDOMAIN' => 'return NXDOMAIN (name does not exist) irrespective of actual result received.',
            'NODATA' => 'returns NODATA (name exists but no answers returned) irrespective of actual result received.',
            'DROP' => 'timeout.',
        );
        return $explanations[$type] . $this->__policies[$policy]['explanation'] . PHP_EOL;
    }

    public function buildHeader($rpzSettings)
    {
        $rpzSettings['serial'] = str_replace('$date', date('Ymd'), $rpzSettings['serial']);
        $header = '';
        $header .= '$TTL ' . $rpzSettings['ttl'] . ';' . PHP_EOL;
        $header .= '@               SOA ' . $rpzSettings['ns'] . ' ' . $rpzSettings['email'] . ' ('  . $rpzSettings['serial'] . ' ' . $rpzSettings['refresh'] . ' ' . $rpzSettings['retry'] . ' ' . $rpzSettings['expiry'] . ' ' . $rpzSettings['minimum_ttl'] . ')' . PHP_EOL;

        if (!empty($rpzSettings['ns_alt'])) {
            $header .= '                NS ' . $rpzSettings['ns'] . PHP_EOL;
            $header .= '                NS ' . $rpzSettings['ns_alt'] . PHP_EOL . PHP_EOL;
        } else {
            $header .= '                NS ' . $rpzSettings['ns'] . PHP_EOL . PHP_EOL;
        }

        return $header;
    }

    public function export($items, $rpzSettings)
    {
        $result = $this->buildHeader($rpzSettings);
        $policy = $this->getPolicyById($rpzSettings['policy']);
        $action = $this->__policies[$policy]['action'];
        if ($policy == 'walled-garden') {
            $action = str_replace('$walled_garden', $rpzSettings['walled_garden'], $action);
        }

        if (isset($items['ip'])) {
            $result .= $this->explain('ip', $policy);
            foreach ($items['ip'] as $item) {
                $result .= $this->__convertIP($item, $action);
            }
            $result .= PHP_EOL;
        }

        if (isset($items['domain'])) {
            $result .= $this->explain('domain', $policy);
            foreach ($items['domain'] as $item) {
                $result .= $this->__convertdomain($item, $action);
            }
            $result .= PHP_EOL;
        }

        if (isset($items['hostname'])) {
            $result .= $this->explain('hostname', $policy);
            foreach ($items['hostname'] as $item) {
                $result .= $this->__converthostname($item, $action);
            }
            $result .= PHP_EOL;
        }
        return $result;
    }

    private function __convertdomain($input, $action)
    {
        return $input . ' CNAME ' . $action . PHP_EOL . '*.' . $input . ' CNAME ' . $action . PHP_EOL;
    }

    private function __converthostname($input, $action)
    {
        return $input . ' CNAME ' . $action . PHP_EOL;
    }

    private function __convertIP($input, $action)
    {
        $type = filter_var($input, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'ipv6' : 'ipv4';
        if ($type == 'ipv6') {
            $prefix = '128';
        } else {
            $prefix = '32';
        }
        if (strpos($input, '/')) {
            list($input, $prefix) = explode('/', $input);
        }
        return $prefix . '.' . $this->{'__' . $type}($input) . '.rpz-ip CNAME ' . $action . PHP_EOL;
    }

    private function __ipv6($input)
    {
        return implode('.', array_reverse(preg_split('/:/', str_replace('::', ':zz:', $input), null, PREG_SPLIT_NO_EMPTY)));
    }

    private function __ipv4($input)
    {
        return implode('.', array_reverse(explode('.', $input)));
    }
}
