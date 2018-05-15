<?php
	class EventTimelineTool {

		private $__lookupTables = array();
		private $__user = false;
		private $__json = array();
		private $__eventModel = false;
		private $__refModel = false;
		# Will be use latter on
		private $__related_events = array();
		private $__related_attributes = array();

		public function construct($eventModel, $user, $filterRules, $extended_view=0) {
			$this->__eventModel = $eventModel;
			$this->__user = $user;
			$this->__filterRules = $filterRules;
			$this->__json = array();
			$this->__extended_view = $extended_view;
			$this->__lookupTables = array(
				'analysisLevels' => $this->__eventModel->analysisLevels,
				'distributionLevels' => $this->__eventModel->Attribute->distributionLevels
			);
			return true;
		}

		public function construct_for_ref($refModel, $user) {
			$this->__refModel = $refModel;
			$this->__user = $user;
			$this->__json = array();
			return true;
		}

		private function __get_event($id) {
			$fullevent = $this->__eventModel->fetchEvent($this->__user, array('eventid' => $id, 'flatten' => 0, 'includeTagRelations' => 1, 'extended' => $this->__extended_view));
			$event = array();
			if (empty($fullevent)) return $event;

			if (!empty($fullevent[0]['Object'])) {
				$event['Object'] = $fullevent[0]['Object'];
			} else {
				$event['Object'] = array();
			}

			if (!empty($fullevent[0]['Attribute'])) {
				$event['Attribute'] = $fullevent[0]['Attribute'];
			} else {
				$event['Attribute'] = array();
			}

			return $event;
		}

		public function get_timeline($id) {
			$event = $this->__get_event($id);
			$this->__json['items'] = array();
			
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

			// extract links and node type
			foreach ($attribute as $attr) {
				$toPush = array(
					'id' => $attr['id'],
					'uuid' => $attr['uuid'],
					'content' => $attr['value'],
					'event_id' => $attr['event_id'],
					'group' => 'attribute',
					'timestamp' => $attr['timestamp'],
				);
				array_push($this->__json['items'], $toPush);
			}

			foreach ($object as $obj) {
				$toPush_obj = array(
					'id' => $obj['id'],
					'uuid' => $obj['uuid'],
					'content' => $obj['name'],
					'group' => 'object',
					'meta-category' => $obj['meta-category'],
					'template_uuid' => $obj['template_uuid'],
					'event_id' => $obj['event_id'],
					'timestamp' => $attr['timestamp'],
					'Attribute' => array(),
				);

				foreach($obj['Attribute'] as $obj_attr) {
					$toPush_attr = array(
						'id' => $obj_attr['id'],
						'uuid' => $obj_attr['uuid'],
						'content' => $obj_attr['value'],
						'contentType' => $obj_attr['object_relation'],
						'event_id' => $obj_attr['event_id'],
						'group' => 'object_attribute',
						'timestamp' => $attr['timestamp'],
					);
					array_push($toPush_obj['Attribute'], $toPush_attr);
				}
				array_push($this->__json['items'], $toPush_obj);
			}

			return $this->__json;
		}
	}
?>
