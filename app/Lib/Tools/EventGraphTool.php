<?php
	class EventGraphTool {

		private $__lookupTables = array();
		private $__user = false;
		private $__json = array();
		private $__eventModel = false;
		private $__refModel = false;
		# Will be use latter on
		private $__related_events = array();
		private $__related_attributes = array();

		public function construct($eventModel, $user) {
			$this->__eventModel = $eventModel;
			$this->__user = $user;
			$this->__json = array();
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
			$fullevent = $this->__eventModel->fetchEvent($this->__user, array('eventid' => $id, 'flatten' => 0, 'includeTagRelations' => 1));
			$event = array();
			if (empty($fullevent)) return $event;

			if (!empty($fullevent[0]['Object'])) {
				$event['Object'] = $fullevent[0]['Object'];
			}
			if (!empty($fullevent[0]['Attribute'])) {
				$event['Attribute'] = $fullevent[0]['Attribute'];
			}
			return $event;
		}

		private function __get_filtered_event($id, $filterRules) {
			$event = $this->__get_event($id);
			if (empty($filterRules)) return $event;

			// perform filtering
			debug($filterRules);
			return $event;
		}

		public function get_references($id, $filterRules=array()) {
			$event = $this->__get_filtered_event($id, $filterRules);
			$this->__json['items'] = array();
			$this->__json['relations'] = array();
			$this->__json['existing_object_relation'] = array();
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
					'type' => $attr['type'],
					'label' => $attr['value'],
					'node_type' => 'attribute',
				);
				array_push($this->__json['items'], $toPush);
			}

			foreach ($object as $obj) {
				$toPush = array(
					'id' => $obj['id'],
					'uuid' => $obj['uuid'],
					'type' => $obj['name'],
					'Attribute' => $obj['Attribute'],
					'label' => '',
					'node_type' => 'object',
					'meta-category' => $obj['meta-category'],
					'template_uuid' => $obj['template_uuid'],
				);
				array_push($this->__json['items'], $toPush);

				// Record existing object_relation
				foreach ($obj['Attribute'] as $attr) {
					$this->__json['existing_object_relation'][$attr['type']] = 0; // set-alike
				}

				foreach($obj['ObjectReference'] as $rel) {
					$toPush = array(
						'id' => $rel['id'],
						'uuid' => $rel['uuid'],
						'from' => $obj['id'],
						'to' => $rel['referenced_id'],
						'type' => $rel['relationship_type'],
						'comment' => $rel['comment'],
					);
					array_push($this->__json['relations'], $toPush);
				}
			}

			return $this->__json;
		}

		public function get_tag($id) {
			// to do
		}

		public function get_distribution($id) {
			// to do
		}

		public function get_reference_data($uuid) {
			$objectReference = $this->__refModel->ObjectReference->find('all', array(
				'conditions' => array('ObjectReference.uuid' => $uuid),
				'recursive' => -1,
				//'fields' => array('ObjectReference.id', 'relationship_type', 'comment', 'referenced_uuid')
				));
			if (empty($objectReference)) throw new NotFoundException('Invalid object reference');
			return $objectReference;
		}

		public function get_object_templates() {
			$templates = $this->__refModel->ObjectTemplate->find('all', array(
				'recursive' => -1,
				'contain' => array(
					'ObjectTemplateElement'
				)
			));
			if (empty($templates)) throw new NotFoundException('No templates');
			return $templates;
		}
  	}
?>
