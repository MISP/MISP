<?php

class RPZExport
{
    const POLICIES = array(
        'Local-Data' => array(
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
        'PASSTHRU' => array(
            'explanation' => 'lets queries through, but allows for logging the hits (useful for testing).',
            'action' => 'rpz-passthru.',
            'setting_id' => 4,
        ),
        'TCP-only' => array(
            'explanation' => 'force the client to use TCP.',
            'action' => 'rpz-tcp-only.',
            'setting_id' => 5,
        ),
    );

	private $items = array();

	public $additional_params = array(
		'flatten' => 1
	);

	private $rpzSettings = array();

	private $__server = null;

	const VALID_TYPES = array(
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
			$this->attributeHandler($data);
		} else {
			$this->eventHandler($data);
		}
        return '';
	}

	private function eventHandler($event)
    {
		foreach ($event['Attribute'] as $attribute) {
			if (isset(self::VALID_TYPES[$attribute['type']])) {
				if ($attribute['type'] === 'domain|ip') {
					$temp = explode('|', $attribute['value']);
					$attribute['value1'] = $temp[0];
					$attribute['value2'] = $temp[1];
				}
				$this->attributeHandler(array('Attribute' => $attribute));
			}
		}
	}

	private function attributeHandler($attribute)
	{
		if (isset($attribute['Attribute'])) {
			$attribute = $attribute['Attribute'];
		}
		if (isset(self::VALID_TYPES[$attribute['type']])) {
			foreach (self::VALID_TYPES[$attribute['type']] as $field => $mapping) {
				if (!isset($this->items[$mapping][$attribute[$field]])) {
					$this->items[$mapping][$attribute[$field]] = true;
				}
			}
		}
	}

	public function header($options = array())
	{
		$lookupData = array('policy', 'walled_garden', 'ns', 'ns_alt', 'email', 'serial', 'refresh', 'retry', 'expiry', 'minimum_ttl', 'ttl');
		foreach ($lookupData as $v) {
			if ($v === 'policy' && isset($options['filters'][$v])) {
				if (!in_array($options['filters'][$v], array('NXDOMAIN', 'NODATA', 'DROP', 'Local-Data', 'PASSTHRU', 'TCP-only'))) {
					unset($options['filters'][$v]);
				} else {
					$options['filters'][$v] = $this->getIdByPolicy($options['filters'][$v]);
				}
			}
			if (isset($options['filters'][$v])) {
				$this->rpzSettings[$v] = $options['filters'][$v];
			} else {
				$tempSetting = Configure::read('Plugin.RPZ_' . $v);
				if (isset($tempSetting)) {
					$this->rpzSettings[$v] = $tempSetting;
				} else {
					if (empty($this->__server)) {
						$this->__server = ClassRegistry::init('Server');
					}
					$this->rpzSettings[$v] = $this->__server->serverSettings['Plugin']['RPZ_' . $v]['value'];
				}
			}
		}
		return '';
	}

	public function footer($options = array())
	{
		return $this->export($this->items, $this->rpzSettings);
	}

	public function separator()
	{
		return '';
	}

    private function getPolicyById($id)
    {
        foreach (self::POLICIES as $k => $v) {
            if ($id === $v['setting_id']) {
                return $k;
            }
        }
        return null;
    }

    private function getIdByPolicy($policy)
    {
        return self::POLICIES[$policy]['setting_id'];
    }

    private function explain($type, $policy)
    {
        $explanations = array(
            'ip' => '; The following list of IP addresses will ',
            'domain' => '; The following domain names and all of their sub-domains will ',
            'hostname' => '; The following hostnames will '
        );
        return $explanations[$type] . self::POLICIES[$policy]['explanation'] . PHP_EOL;
    }

    private function buildHeader(array $rpzSettings)
    {
        $rpzSettings['serial'] = str_replace('$date', date('Ymd'), $rpzSettings['serial']);
        $rpzSettings['serial'] = str_replace('$time', time(), $rpzSettings['serial']);
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

    private function export(array $items, array $rpzSettings)
    {
        $result = $this->buildHeader($rpzSettings);
        $policy = $this->getPolicyById($rpzSettings['policy']);
        $action = self::POLICIES[$policy]['action'];
        if ($policy === 'Local-Data') {
            $action = str_replace('$walled_garden', $rpzSettings['walled_garden'], $action);
        }

        if (isset($items['ip'])) {
            $result .= $this->explain('ip', $policy);
            foreach ($items['ip'] as $item => $foo) {
                $result .= $this->convertIp($item, $action);
            }
            $result .= PHP_EOL;
        }

        if (isset($items['domain'])) {
            $result .= $this->explain('domain', $policy);
            foreach ($items['domain'] as $item => $foo) {
                $result .= $this->convertDomain($item, $action);
            }
            $result .= PHP_EOL;
        }

        if (isset($items['hostname'])) {
            $result .= $this->explain('hostname', $policy);
            foreach ($items['hostname'] as $item => $foo) {
                $result .= $this->convertHostname($item, $action);
            }
            $result .= PHP_EOL;
        }
        return $result;
    }

    private function convertDomain($input, $action)
    {
        return $input . ' CNAME ' . $action . PHP_EOL . '*.' . $input . ' CNAME ' . $action . PHP_EOL;
    }

    private function convertHostname($input, $action)
    {
        return $input . ' CNAME ' . $action . PHP_EOL;
    }

    private function convertIp($input, $action)
    {
        $isIpv6 = filter_var($input, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        if ($isIpv6) {
            $prefix = '128';
        } else {
            $prefix = '32';
        }
        if (strpos($input, '/')) {
            list($input, $prefix) = explode('/', $input);
        }
        $converted = $isIpv6 ? $this->__ipv6($input) : $this->__ipv4($input);
        return $prefix . '.' . $converted . '.rpz-ip CNAME ' . $action . PHP_EOL;
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
