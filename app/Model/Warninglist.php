<?php
App::uses('AppModel', 'Model');
class Warninglist extends AppModel{
	public $useTable = 'warninglists';
	public $recursive = -1;
	public $actsAs = array(
			'Containable',
	);

	public $validate = array(
		'name' => array(
			'rule' => array('valueNotEmpty'),
		),
		'description' => array(
			'rule' => array('valueNotEmpty'),
		),
		'version' => array(
			'rule' => array('numeric'),
		),
	);

	public $hasMany = array(
			'WarninglistEntry' => array(
				'dependent' => true
			),
			'WarninglistType' => array(
				'dependent' => true
			)
	);

	public function beforeValidate($options = array()) {
		parent::beforeValidate();
		return true;
	}

	public function checkValidTypeJSON($check) {
		return true;
	}

	public function update() {
		$directories = glob(APP . 'files' . DS . 'warninglists' . DS . 'lists' . DS . '*', GLOB_ONLYDIR);
		$updated = array();
		foreach ($directories as &$dir) {
			$file = new File($dir . DS . 'list.json');
			$list = json_decode($file->read(), true);
			$file->close();
			if (!isset($list['version'])) $list['version'] = 1;
			if (!isset($list['type'])) {
				$list['type'] = 'string';
			} else if (is_array($list['type'])) {
				$list['type'] = $list['type'][0];
			}
			$current = $this->find('first', array(
					'conditions' => array('name' => $list['name']),
					'recursive' => -1,
					'fields' => array('*')
			));
			if (empty($current) || $list['version'] > $current['Warninglist']['version']) {
				$result = $this->__updateList($list, $current);
				if (is_numeric($result)) {
					$updated['success'][$result] = array('name' => $list['name'], 'new' => $list['version']);
					if (!empty($current)) $updated['success'][$result]['old'] = $current['Warninglist']['version'];
				} else {
					$updated['fails'][] = array('name' => $list['name'], 'fail' => json_encode($result));
				}
			}
		}
		return $updated;
	}

	private function __updateList($list, $current) {
		$list['enabled'] = false;
		$warninglist = array();
		if (!empty($current)) {
			if ($current['Warninglist']['enabled']) $list['enabled'] = true;
			$this->deleteAll(array('Warninglist.id' => $current['Warninglist']['id']));
		}
		$fieldsToSave = array('name', 'version', 'description', 'type', 'enabled');
		foreach ($fieldsToSave as $fieldToSave) {
			$warninglist['Warninglist'][$fieldToSave] = $list[$fieldToSave];
		}
		$this->create();
		if ($this->save($warninglist)) {
			$data = array();
			foreach ($list['list'] as $value) {
				$data[] = array('value' => $value, 'warninglist_id' => $this->id);
			}
			$this->WarninglistEntry->saveMany($data);

			if (!empty($list['matching_attributes'])) {
				$data = array();
				foreach ($list['matching_attributes'] as $type) {
					$data[] = array('type' => $type, 'warninglist_id' => $this->id);
				}
				$this->WarninglistType->saveMany($data);
			} else {
				$this->WarninglistType->create();
				$this->WarninglistType->save(array('WarninglistType' => array('type' => 'ALL', 'warninglist_id' => $this->id)));
			}
			return $this->id;
		} else {
			return $this->validationErrors;
		}
	}

	public function fetchForEventView() {
		$warninglists = $this->find('all', array('contain' => array('WarninglistType'), 'conditions' => array('enabled' => true)));
		if (empty($warninglists)) return array();
		foreach ($warninglists as $k => &$t) {
			$t['values'] = $this->WarninglistEntry->find('list', array(
					'recursive' => -1,
					'conditions' => array('warninglist_id' => $t['Warninglist']['id']),
					'fields' => array('value')
			));
			$t['values'] = array_values($t['values']);
			foreach ($t['WarninglistType'] as &$wt) {
				$t['types'][] = $wt['type'];
			}
			unset($warninglists[$k]['WarninglistType']);
		}
		return $warninglists;
	}

	public function setWarnings(&$event, &$warninglists) {
		if (empty($event['objects'])) return $event;
		$eventWarnings = array();
		foreach ($event['objects'] as &$object) {
			if ($object['to_ids']) {
				foreach ($warninglists as &$list) {
					if (in_array('ALL', $list['types']) || in_array($object['type'], $list['types'])) {
						$result = $this->__checkValue($list['values'], $object['value'], $object['type'], $list['Warninglist']['type']);
						if (!empty($result)) {
							$object['warnings'][$result][] = $list['Warninglist']['name'];
							if (!in_array($list['Warninglist']['name'], $eventWarnings)) {
								$eventWarnings[$list['Warninglist']['id']] = $list['Warninglist']['name'];
							}
						}
					}
				}
			}
		}
		$event['Event']['warnings'] = $eventWarnings;
		return $event;
	}

	private function __checkValue(&$listValues, $value, $type, $listType) {
		if (strpos($type, '|')) $value = explode('|', $value);
		else $value = array($value);
		$components = array(0, 1);
		foreach ($components as $component) {
			if (!isset($value[$component])) continue;
			if ($listType === 'cidr') {
				$result = $this->__evalCIDRList($listValues, $value[$component]);
			} else if ($listType === 'string') {
				$result = $this->__evalString($listValues, $value[$component]);
			}
			if ($result) return ($component + 1);
		}
		return false;
	}

	// This requires an IP type attribute in a non CIDR notation format
	// For the future we can expand this to look for CIDR overlaps?
	private function __evalCIDRList(&$listValues, $value) {
		$ipv4cidrlist = array();
		$ipv6cidrlist = array();
		// separate the CIDR list into IPv4 and IPv6
		foreach ($listValues as $lv) {
			$base = substr($lv, 0, strpos($lv, '/'));
			if (filter_var($base, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
				$ipv4cidrlist[] = $lv;
			} else if (filter_var($base, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
				$ipv6cidrlist[] = $lv;
			}
		}
		// evaluate the value separately for IPv4 and IPv6
		if (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			return $this->__evalCIDR($value, $ipv4cidrlist, '__ipv4InCidr');
		} else if (filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
			return $this->__evalCIDR($value, $ipv6cidrlist, '__ipv6InCidr');
		}
		return false;

	}

	private function __evalCIDR($value, &$listValues, $function) {
		$found = false;
		foreach ($listValues as $lv) {
			$found = $this->$function($value, $lv);
		}
		if ($found) return true;
		return false;
	}

	// using Alnitak's solution from http://stackoverflow.com/questions/594112/matching-an-ip-to-a-cidr-mask-in-php5
	private function __ipv4InCidr($ip, $cidr) {
		list ($subnet, $bits) = explode('/', $cidr);
		$ip = ip2long($ip);
		$subnet = ip2long($subnet);
		$mask = -1 << (32 - $bits);
		$subnet &= $mask; # nb: in case the supplied subnet wasn't correctly aligned
		return ($ip & $mask) == $subnet;
	}

	// using Snifff's solution from http://stackoverflow.com/questions/7951061/matching-ipv6-address-to-a-cidr-subnet
	private function __ipv6InCidr($ip, $cidr) {
		$ip = inet_pton($ip);
		$binaryip = $this->__inet_to_bits($ip);
		list($net, $maskbits) = explode('/', $cidr);
		$net = inet_pton($net);
		$binarynet = $this->__inet_to_bits($net);
		$ip_net_bits = substr($binaryip, 0, $maskbits);
		$net_bits = substr($binarynet, 0, $maskbits);
		return ($ip_net_bits === $net_bits);
	}

	// converts inet_pton output to string with bits
	private function __inet_to_bits($inet) {
		$unpacked = unpack('A16', $inet);
		$unpacked = str_split($unpacked[1]);
		$binaryip = '';
		foreach ($unpacked as $char) {
			$binaryip .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
		}
		return $binaryip;
	}

	private function __evalString(&$listValues, $value) {
		if (in_array($value, $listValues)) return true;
		return false;
	}
}
