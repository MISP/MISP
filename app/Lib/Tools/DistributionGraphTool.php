<?php
	class DistributionGraphTool {

		private $__lookupTables = array();
		private $__user = false;
		private $__json = array();
		private $__eventModel = false;
		private $__refModel = false;
		# Will be use latter on
		private $__related_events = array();
		private $__related_attributes = array();

		public function construct($eventModel, $serverModel, $orgModel, $user, $extended_view=0) {
			$this->__eventModel = $eventModel;
			$this->__serverModel = $serverModel;
			$this->__organisationModel = $orgModel;
			$this->__user = $user;
			$this->__json = array();
			$this->__extended_view = $extended_view;

			// construct distribution info
			$this->__json['distributionInfo'] = array();
			$sgs = $this->__eventModel->SharingGroup->fetchAllAuthorised($this->__user, 'name',  1);
			$this->__json['allSharingGroup'] = array_values($sgs);
			$distributionLevels = $this->__eventModel->distributionLevels;
			if (empty($sgs)) unset($distributionLevels[4]);
			foreach ($distributionLevels as $key => $value) {
				$this->__json['distributionInfo'][$key] = array('key' => $value, 'desc' => $this->__eventModel->distributionDescriptions[$key]['formdesc'], 'value' => $key);
			}
			$this->__json['distributionInfo'][5] = ""; // inherit event. Will be deleted afterward

			$this->__lookupTables = array(
				'analysisLevels' => $this->__eventModel->analysisLevels,
				'distributionLevels' => $this->__eventModel->Attribute->distributionLevels
			);
			return true;
		}

		private function __extract_sharing_groups_names($sharingArray) {
			return $sharingArray['name'];
		}

		private function __fetchAndAddDistributionInfo($elem) {
			$distributionLevel = $elem['distribution'];

			if ($distributionLevel == 4) { // sharing group
				$sg_name = $this->__extract_sharing_groups_names($elem['SharingGroup']);
				$this->__addAdditionalDistributionInfo($distributionLevel, $sg_name);

			} else if ($distributionLevel == 3) { // all
				if (empty($this->__json['additionalDistributionInfo'][$distributionLevel])) {
					$servers = $this->__serverModel->find('list', array(
						'fields' => array('name'),
					));
					$this->__addAdditionalDistributionInfo($distributionLevel, "This community"); // add current community
					$this->__addAdditionalDistributionInfo($distributionLevel, "All other communities"); // add current community
				} else {
					return false;
				}

			} else if ($distributionLevel == 2) { // connected
				// fetch connected communities
				if (empty($this->__json['additionalDistributionInfo'][$distributionLevel])) {
					$servers = $this->__serverModel->find('list', array(
						'fields' => array('name'),
					));
					$this->__addAdditionalDistributionInfo($distributionLevel, "This community"); // add current community
					foreach ($servers as $server) {
						$this->__addAdditionalDistributionInfo($distributionLevel, $server);
					}
				} else {
					return false;
				}

			} else if ($distributionLevel == 1) { // community
				if (empty($this->__json['additionalDistributionInfo'][$distributionLevel])) {
					$orgs = $this->__organisationModel->find('list', array(
						'fields' => array('name'),
					));
					$thisOrg = $this->__user['Organisation']['name'];
					$this->__addAdditionalDistributionInfo($distributionLevel, $thisOrg); // add current community
					foreach ($orgs as $org) {
						if ($thisOrg != $org) {
							$this->__addAdditionalDistributionInfo($distributionLevel, $org);
						}
					}
				} else {
					return false;
				}
				
			} else if ($distributionLevel == 0) { // org only
				if (empty($this->__json['additionalDistributionInfo'][$distributionLevel])) {
					$thisOrg = $this->__user['Organisation']['name'];
					$this->__addAdditionalDistributionInfo($distributionLevel, $thisOrg); // add current community
				} else {
					return false;
				}
				
			} else {
				return false;
			}
			return true;
		}

		private function __addAdditionalDistributionInfo($distributionLevel, $data) {
			if (empty($this->__json['additionalDistributionInfo'][$distributionLevel])) {
				$this->__json['additionalDistributionInfo'][$distributionLevel] = array();
			}
			array_push($this->__json['additionalDistributionInfo'][$distributionLevel], $data);
		}

		private function __get_event($id) {
			$fullevent = $this->__eventModel->fetchEvent($this->__user, array('eventid' => $id, 'flatten' => 0, 'includeTagRelations' => 1, 'extended' => $this->__extended_view));
			$event = array();
			if (empty($fullevent)) return $event;

			$fullevent = $fullevent[0];
			if (!empty($fullevent['Object'])) {
				$event['Object'] = $fullevent['Object'];
			} else {
				$event['Object'] = array();
			}

			if (!empty($fullevent['Attribute'])) {
				$event['Attribute'] = $fullevent['Attribute'];
			} else {
				$event['Attribute'] = array();
			}
			$event['distribution'] = $fullevent['Event']['distribution'];

			return $event;
		}

		public function get_distributions_graph($id) {
			$event = $this->__get_event($id);
			$eventDist = $event['distribution'];
			$this->__json['event'] = $this->init_array_distri();
			$this->__json['attribute'] = $this->init_array_distri();
			$this->__json['object'] = $this->init_array_distri();
			$this->__json['obj_attr'] = $this->init_array_distri();
			$this->__json['additionalDistributionInfo'] = $this->init_array_distri(array());

			
			if (empty($event)) return $this->__json;
			
			if (!empty($event['Object'])) {
				$object = $event['Object'];
			} else {
				$object = array();
			}

			if (!empty($event['Attribute'])) {
				$attribute = $event['Attribute'];
			} else {
				$attribute = array();
			}

			// extract distribution
			foreach ($attribute as $attr) {
				$distri = $attr['distribution'];
				$this->__json['event'][$distri] += 1;
				$this->__json['attribute'][$distri] += 1;
				$this->__fetchAndAddDistributionInfo($attr);
			}

			foreach ($object as $obj) {
				$distri = $obj['distribution'];
				$this->__json['event'][$distri] += 1;
				$this->__json['object'][$distri] += 1;
				$this->__fetchAndAddDistributionInfo($obj);

				$added_value = array();
				foreach($obj['Attribute'] as $objAttr) {
					$distri = $objAttr['distribution'];
					$this->__json['event'][$distri] += 1;
					$this->__json['obj_attr'][$distri] += 1;
					$this->__fetchAndAddDistributionInfo($objAttr);
				}
			}
			// distribution 5 is inherit event, apply this fact on values
			$this->__json['event'][$eventDist] += $this->__json['event'][5];
			unset($this->__json['event'][5]);
			$this->__json['attribute'][$eventDist] += $this->__json['attribute'][5];
			unset($this->__json['attribute'][5]);
			$this->__json['object'][$eventDist] += $this->__json['object'][5];
			unset($this->__json['object'][5]);
			$this->__json['obj_attr'][$eventDist] += $this->__json['obj_attr'][5];
			unset($this->__json['obj_attr'][5]);

			unset($this->__json['distributionInfo'][5]); // inherit event.


			$this->__json['additionalDistributionInfo'] = $this->__json['additionalDistributionInfo'];
			return $this->__json;
		}

		public function init_array_distri($default=0) {
			$ret = array();
			foreach ($this->__json['distributionInfo'] as $d => $v) {
				$ret[$d] = $default;
			}
			return $ret;
		}
	}

?>
