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

		public function construct($eventModel, $user, $extended_view=0) {
			$this->__eventModel = $eventModel;
			$this->__user = $user;
			$this->__json = array();
			$this->__extended_view = $extended_view;

			// construct distribution info
			$this->__json['distributionInfo'] = array();
			$sgs = $this->__eventModel->SharingGroup->fetchAllAuthorised($this->__user, 'name',  1);
			$distributionLevels = $this->__eventModel->distributionLevels;
			if (empty($sgs)) unset($distributionLevels[4]);
			foreach ($distributionLevels as $key => $value) {
				$this->__json['distributionInfo'][$key] = array('key' => $value, 'desc' => $this->__eventModel->distributionDescriptions[$key]['formdesc']);
			}
			$this->__json['distributionInfo'][5] = ""; // inherit event. Will be deleted afterward


			$this->__lookupTables = array(
				'analysisLevels' => $this->__eventModel->analysisLevels,
				'distributionLevels' => $this->__eventModel->Attribute->distributionLevels
			);
			return true;
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
				$toPush = array(
					'id' => $attr['id'],
					'uuid' => $attr['uuid'],
					'type' => $attr['type'],
					'label' => $attr['value'],
					'event_id' => $attr['event_id'],
					'distribution' => $attr['distribution'],
				);
				//array_push($this->__json['items'], $toPush);
				$distri = $attr['distribution'];
				$this->__json['event'][$distri] += 1;
				$this->__json['attribute'][$distri] += 1;
			}

			foreach ($object as $obj) {
				$toPush = array(
					'id' => $obj['id'],
					'uuid' => $obj['uuid'],
					'type' => $obj['name'],
					'label' => 'Ojbect' . $obj['id'],
					'meta-category' => $obj['meta-category'],
					'event_id' => $obj['event_id'],
					'distribution' => $obj['distribution'],
				);
				//array_push($this->__json['items'], $toPush);
				$distri = $obj['distribution'];
				$this->__json['event'][$distri] += 1;
				$this->__json['object'][$distri] += 1;

				$added_value = array();
				foreach($obj['Attribute'] as $objAttr) {
					$toPush = array(
						'id' => $objAttr['id'],
						'uuid' => $objAttr['uuid'],
						'type' => $objAttr['type'],
						'label' => $objAttr['value'],
						'belongTo' => $obj['id'],
						'event_id' => $objAttr['event_id'],
						'distribution' => $objAttr['distribution'],
					);
					//array_push($this->__json['items'], $toPush);
					$distri = $objAttr['distribution'];
					$this->__json['event'][$distri] += 1;
					$this->__json['obj_attr'][$distri] += 1;
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
			return $this->__json;
		}

		public function init_array_distri() {
			$ret = array();
			foreach ($this->__json['distributionInfo'] as $d => $v) {
				$ret[$d] = 0;
			}
			return $ret;
		}
	}

?>
