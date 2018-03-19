<?php
	class ReferencesGraphTool {

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
		public function get_all_data($id) {
			$event = $this->__eventModel->fetchEvent($this->__user, array('eventid' => $id, 'flatten' => 0, 'includeTagRelations' => 1));
			if (empty($event)) return $this->__json;
			//return $event;
			if (!empty($event[0]['Object'])) {
				$this->__json['Object'] = $event[0]['Object'];
			}
			if (!empty($event[0]['Attribute'])) {
				$this->__json['Attribute'] = $event[0]['Attribute'];
			}
			return $this->__json;
		}
  }
?>
