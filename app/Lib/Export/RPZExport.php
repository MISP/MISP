<?php

class RPZExport {
	
	public function explain($type, $policy) {
		$explanations = array(
				'ip' => '# The following list of IP addresses will ',
				'domain' => '# The following domain names and all of their sub-domains will ',
				'hostname' => '# The following hostnames will '
		);
		$policy_explanations = array(
			'walled-garden' => 'returns the defined alternate location.',
			'NXDOMAIN' => 'return NXDOMAIN (name does not exist) irrespective of actual result received.',
			'NODATA' => 'returns NODATA (name exists but no answers returned) irrespective of actual result received.',
			'DROP' => 'timeout.',
		);
		return $explanations[$type] . $policy_explanations[$policy] . PHP_EOL . PHP_EOL;
	}
	
	private function __buildHeader() {
		$header = '';
		return $header;
	}
	
	public function export($items, $rpzSettings) {
		$result = '';
		switch ($rpzSettings['policy']) {
			case 0:
				$policy = 'DROP';
				$action = 'rpz-drop.';
				break;
			case 1:
				$policy = 'NXDOMAIN';
				$action = '.';
				break;
			case 2:
				$policy = 'NODATA';
				$action = '*.';
				break;
			case 3:
				$policy = 'walled-garden';
				$action = $rpzSettings['walled'];
				break;
		}
		
		if (isset($items['ip'])) {
			$result .= $this->explain('ip', $policy);
			foreach ($items['ip'] as $item) {
				$result .= $this->__convertIP($item, $action);
			}
		}
		
		if (isset($items['domain'])) {
			$result .= $this->explain('domain', $policy);
			foreach ($items['domain'] as $item) {
				$result .= $this->__convertdomain($item, $action);
			}
		}
		
		if (isset($items['hostname'])) {
			$result .= $this->explain('hostname', $policy);
			foreach ($items['hostname'] as $item) {
				$result .= $this->__converthostname($item, $action);
			}
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
