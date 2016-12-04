<?php
App::uses('AppModel', 'Model');
class Galaxy extends AppModel{

	public $useTable = 'galaxies';

	public $recursive = -1;

	public $actsAs = array(
			'Containable',
	);

	public $validate = array(
	);

	public $hasMany = array(
		'GalaxyCluster' => array('dependent' => true)
	);

	public function beforeValidate($options = array()) {
		parent::beforeValidate();
		return true;
	}
	
	public function beforeDelete($cascade = true) {
		$this->GalaxyCluster->deleteAll(array('GalaxyCluster.galaxy_id' => $this->id));
	}

	private function __load_galaxies() {
		$dir = new Folder(APP . 'files' . DS . 'misp-galaxy' . DS . 'galaxies');
		$files = $dir->find('.*\.json');
		$galaxies = array();
		foreach ($files as $file) {
			$file = new File($dir->pwd() . DS . $file);
			$galaxies[] = json_decode($file->read(), true);
			$file->close();
		}
		foreach ($galaxies as $galaxy) {
			$this->deleteAll(array('Galaxy.type' => $galaxy['type']));
		}
		$this->saveMany($galaxies);
		return $this->find('list', array('recursive' => -1, 'fields' => array('type', 'id')));
	}
	
	public function update() {
		$galaxies = $this->__load_galaxies();
		$dir = new Folder(APP . 'files' . DS . 'misp-galaxy' . DS . 'clusters');
		$files = $dir->find('.*\.json');
		$cluster_packages = array();
		foreach ($files as $file) {
			$file = new File($dir->pwd() . DS . $file);
			$cluster_packages[] = json_decode($file->read(), true);
			$file->close();
		}
		foreach ($cluster_packages as $cluster_package) {
			if (!isset($galaxies[$cluster_package['type']])) {
				continue;
			}
			$template = array(
				'source' => isset($cluster_package['source']) ? $cluster_package['source'] : '',
				'authors' => json_encode(isset($cluster_package['authors']) ? $cluster_package['authors'] : array(), true),
				'uuid' => isset($cluster_package['uuid']) ? $cluster_package['uuid'] : '',
				'galaxy_id' => $galaxies[$cluster_package['type']],
				'type' => $cluster_package['type'],
				'tag_name' => 'misp-galaxy:' . $cluster_package['type'] . '="'
			);
			foreach ($cluster_package['values'] as $cluster) {
				$this->GalaxyCluster->create();
				$cluster_to_save = $template;
				if (isset($cluster['description'])) {
					$cluster_to_save['description'] = $cluster['description'];
					unset($cluster['description']);
				}
				$cluster_to_save['value'] = $cluster['value'];
				$cluster_to_save['tag_name'] = $cluster_to_save['tag_name'] . $cluster['value'] . '"';
				unset($cluster['value']);
				$this->GalaxyCluster->save($cluster_to_save);
				$galaxyClusterId = $this->GalaxyCluster->id;
				$elements = array();
				if (isset($cluster['meta'])) {
					foreach ($cluster['meta'] as $key => $value) {
						if (is_array($value)) {
							foreach ($value as $v) {
								$elements[] = array(
									'galaxy_cluster_id' => $galaxyClusterId,
									'key' => $key,
									'value' => $v		
								);
							}
						} else {
							$elements[] = array(
								'galaxy_cluster_id' => $this->GalaxyCluster->id,
								'key' => $key,
								'value' => $value
							);
						}
					}
				}
				$this->GalaxyCluster->GalaxyElement->saveMany($elements);
			}
		}
		return true;
	}
	

	private function __updateList($list, $current) {
		$list['enabled'] = 0;
		$warninglist = array();
		if (!empty($current)) {
			if ($current['Warninglist']['enabled']) $list['enabled'] = 1;
			$this->deleteAll(array('Warninglist.id' => $current['Warninglist']['id']));
		}
		$fieldsToSave = array('name', 'version', 'description', 'type', 'enabled');
		foreach ($fieldsToSave as $fieldToSave) {
			$warninglist['Warninglist'][$fieldToSave] = $list[$fieldToSave];
		}
		$this->create();
		if ($this->save($warninglist)) {
			$db = $this->getDataSource();
			$values = array();
			foreach ($list['list'] as $value) {
				if (!empty($value)) {
					$values[] = array($value, $this->id);
				}
			}
			unset($list['list']);
			$result = $db->insertMulti('warninglist_entries', array('value', 'warninglist_id'), $values);
			if ($result) {
				$this->saveField('warninglist_entry_count', count($values));
			} else {
				return 'Could not insert values.';
			}
			if (!empty($list['matching_attributes'])) {
				$values = array();
				foreach ($list['matching_attributes'] as $type) {
					$values[] = array('type' => $type, 'warninglist_id' => $this->id);
				}
				$this->WarninglistType->saveMany($values);
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
		$warninglists = $this->find('all', array('contain' => array('WarninglistType'), 'conditions' => array('enabled' => 1)));
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
				foreach ($warninglists as $list) {
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

	private function __checkValue($listValues, $value, $type, $listType) {
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
	private function __evalCIDRList($listValues, $value) {
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

	private function __evalCIDR($value, $listValues, $function) {
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

	private function __evalString($listValues, $value) {
		if (in_array($value, $listValues)) return true;
		return false;
	}
	
	public function fetchTLDLists() {
		$tldLists = $this->find('list', array('conditions' => array('Warninglist.name' => $this->__tlds, 'Warninglist.enabled' => 1), 'recursive' => -1, 'fields' => array('Warninglist.id', 'Warninglist.name')));
		$tlds = array();
		if (!empty($tldLists)) {
			$tldLists = array_keys($tldLists);
			$tlds = $this->WarninglistEntry->find('list', array('conditions' => array('WarninglistEntry.warninglist_id' => $tldLists), 'fields' => array('WarninglistEntry.value')));	
			if (!empty($tlds)) {
				foreach ($tlds as $key => $value) {
					$tlds[$key] = strtolower($value);
				}
			}
		}
		return $tlds;
	}
}
