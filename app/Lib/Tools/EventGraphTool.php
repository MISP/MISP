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

		public function construct($eventModel, $user, $json) {
			$this->__eventModel = $eventModel;
			$this->__user = $user;
			$this->__json = $json;
			$this->__lookupTables = array(
				'analysisLevels' => $this->__eventModel->analysisLevels,
				'distributionLevels' => $this->__eventModel->Attribute->distributionLevels
			);
			return true;
		}

		public function construct_for_ref($refModel, $user, $json) {
			$this->__refModel = $refModel;
			$this->__user = $user;
			$this->__json = $json;
			return true;
		}

		public function get_all_data($id) {
			$event = $this->__eventModel->fetchEvent($this->__user, array('eventid' => $id, 'flatten' => 0, 'includeTagRelations' => 1));
			if (empty($event)) return $this->__json;

			if (!empty($event[0]['Object'])) {
				$this->__json['Object'] = $event[0]['Object'];
			}
			if (!empty($event[0]['Attribute'])) {
				$this->__json['Attribute'] = $event[0]['Attribute'];
			}
			return $this->__json;
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
  }
?>
