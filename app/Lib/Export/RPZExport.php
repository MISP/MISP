<?php

class RPZExport {
	
	public function explain($type, $policy) {
		$explanations = array(
				'ip' => '# The following list of IP addresses will ',
				'domain' => '# The following domain names and all of their sub-domains will ',
				'hostname' => '# The following hostnames will '
		);
		$policy_explanations = array(
			'NXDOMAIN' => 'return NXDOMAIN (name does not exist) irrespective of actual result received.',
			'NODATA' => 'returns NODATA (name exists but no answers returned) irrespective of actual result received.',
			'DROP' => 'timeout.',
		);
		return $explanations[$type] . $policy_explanations[$policy] . PHP_EOL . PHP_EOL;
	}
	
	public function export($items, $policy) {
		switch ($policy) {
			case 'NXDOMAIN':
				$action = '.';
				break;
			case 'NODATA':
				$action = '*.';
				break;
			default:
				$policy = 'DROP';
				$action = 'rpz-drop.';
		}
		$result = '';
		
		$result .= $this->explain('ip', $policy);
		foreach ($items['ip'] as $item) {
			$result .= $this->__convertIP($item, $action);
		}
		
		$result .= $this->explain('domain', $policy);
		foreach ($items['domain'] as $item) {
			$result .= $this->__convertdomain($item, $action);
		}
		
		$result .= $this->explain('hostname', $policy);
		foreach ($items['hostname'] as $item) {

			$result .= $this->__converthostname($item, $action);
		}
		return $result;
	}

	private function __convertdomain($input, $action) {
		return $input . ' CNAME ' . $action . PHP_EOL . '*.' . $input . ' CNAME ' . $action . PHP_EOL;
	}
	
	private function __converthostname($input, $action) {
		return $input . ' CNAME ' . $action . PHP_EOL;
	}
	
	private function __convertip($input, $action) {
		$type = filter_var($input, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? 'ipv6' : 'ipv4';
		if ($type == 'ipv6') $prefix = '128';
		else $prefix = '32';
		if (strpos($input, '/')) {
			list($input, $prefix) = explode('/', $input);
		}
		return $prefix . '.' . $this->{'__' . $type}($input) . ' CNAME ' . $action . PHP_EOL;
	}
	
	private function __ipv6($input) {
		return implode('.', array_reverse(preg_split('/:/', str_replace('::', ':zz:', $input), NULL, PREG_SPLIT_NO_EMPTY)));
	}
	
	private function __ipv4($input) {
		return implode('.', array_reverse(explode('.', $input)));
		
	}

}
