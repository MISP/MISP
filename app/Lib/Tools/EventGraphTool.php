<?php
  class EventGraphTool {
    public function buildCorrelationGraphJson($id, $eventModel, $user, $json = array()) {
  		$event = $eventModel->fetchEvent($user, array('eventid' => $id, 'flatten' => 1));
  		if (empty($event)) return $json;
  		$json = $this->cleanLinks($json);
  		$old_event = $this->graphJsonContains('event', $event[0]['Event'], $json);
  		if ($old_event !== false) {
  			$json['nodes'][$old_event]['expanded'] = 1;
  			$current_event_id = $old_event;
  		} else {
  			if ($this->orgImgExists($event[0]['Orgc']['name'])) {
  				$image = Configure::read('MISP.baseurl') . '/img/orgs/' . h($event[0]['Orgc']['name']) . '.png';
  			} else {
  				$image = Configure::read('MISP.baseurl') . '/img/orgs/MISP.png';
  			}
  			$json['nodes'][] = array(
  					'name' => '(' . $id . ') ' . (strlen($event[0]['Event']['info']) > 32 ? substr($event[0]['Event']['info'], 0, 31) . '...' : $event[0]['Event']['info']),
  					'type' => 'event',
  					'id' => $id, 'expanded' => 1,
  					'image' => $image,
  					'info' => $event[0]['Event']['info'],
  					'org' => $event[0]['Orgc']['name'],
  					'analysis' => $eventModel->analysisLevels[$event[0]['Event']['analysis']],
  					'distribution' => $eventModel->distributionLevels[$event[0]['Event']['distribution']],
  					'date' => $event[0]['Event']['date']
  			);
  			$current_event_id = count($json['nodes'])-1;
  		}
  		$relatedEvents = array();
  		if (!empty($event[0]['RelatedEvent'])) foreach ($event[0]['RelatedEvent'] as $re) {
  			$relatedEvents[$re['Event']['id']] = $re;
  		}
  		foreach ($event[0]['Attribute'] as $k => $att) {
  			if (isset($event[0]['RelatedAttribute'][$att['id']])) {
  				$current_attribute_id = $this->graphJsonContains('attribute', $att, $json);
  				if ($current_attribute_id === false) {
  					$json['nodes'][] = array(
  							'name' => $att['value'],
  							'type' => 'attribute',
  							'id' => $att['id'],
  							'att_category' => $att['category'],
  							'att_type' => $att['type'],
  							'image' => '/img/indicator.png',
  							'att_ids' => $att['to_ids'],
  							'comment' => $att['comment']
  					);
  					$current_attribute_id = count($json['nodes'])-1;
  				}
  				$l1 = $this->graphJsonContainsLink($current_event_id, $current_attribute_id, $json);
  				if ($l1 === false) $json['links'][] = array('source' => $current_event_id, 'target' => $current_attribute_id);
  				foreach ($event[0]['RelatedAttribute'][$att['id']] as $relation) {
  					$found = $this->graphJsonContains('event', $relation, $json);
  					if ($found !== false) {
  						$l3 = $this->graphJsonContainsLink($found, $current_attribute_id, $json);
  						if ($l3 === false) {
  							$json['links'][] = array('source' => $found, 'target' => $current_attribute_id);
  						}
  					} else {
  						$current_relation_id = $this->graphJsonContains('event', $relation, $json);
  						if ($current_relation_id === false) {
  							if ($this->orgImgExists($relatedEvents[$relation['id']]['Event']['Orgc']['name'])) {
  								$image = '/img/orgs/' . $relatedEvents[$relation['id']]['Event']['Orgc']['name'] . '.png';
  							} else {
  								$image = '/img/orgs/MISP.png';
  							}
  							$json['nodes'][] = array(
  									'name' => '(' . $relation['id'] . ') ' . (strlen($relatedEvents[$relation['id']]['Event']['info']) > 32 ? substr($relatedEvents[$relation['id']]['Event']['info'], 0, 31) . '...' : $relatedEvents[$relation['id']]['Event']['info']),
  									'type' => 'event', 'id' => $relation['id'],
  									'expanded' => 0, 'image' => $image,
  									'info' => $relatedEvents[$relation['id']]['Event']['info'],
  									'org' => $relatedEvents[$relation['id']]['Event']['Orgc']['name'],
  									'analysis' => $eventModel->analysisLevels[$relatedEvents[$relation['id']]['Event']['analysis']],
  									'date' => $relatedEvents[$relation['id']]['Event']['date']
  							);
  							$current_relation_id = count($json['nodes'])-1;
  						}
  						$l2 = $this->graphJsonContainsLink($current_attribute_id, $current_relation_id, $json);
  						if ($l2 === false) {
  							$json['links'][] = array('source' => $current_attribute_id, 'target' => $current_relation_id);
  						}
  					}
  				}
  			}
  		}
  		return $json;
  	}

  	public function cleanLinks($json) {
  		if (isset($json['nodes']) && isset($json['links'])) {
  			$links = array();
  			foreach ($json['links'] as $link) {
  				$temp = array();
  				foreach ($json['nodes'] as $k => $node) {
  					if ($link['source'] == $node) $temp['source'] = $k;
  					if ($link['target'] == $node) $temp['target'] = $k;
  				}
  				$links[] = $temp;
  			}
  			$json['links'] = $links;
  		} else {
  			if (!isset($json['links'])) {
  				$json['links'] = array();
  			}
  			if (!isset($json['nodes'])) {
  				$json['nodes'] = array();
  			}
  		}
  		return $json;
  	}

  	public function orgImgExists($org) {
  		if (file_exists(APP . 'webroot' . DS . 'img' . DS . 'orgs' . DS . $org . '.png')) {
  			return true;
  		}
  		return false;
  	}

  	public function graphJsonContains($type, $att, $json) {
  		if (!isset($json['nodes'])) return false;
  		foreach ($json['nodes'] as $k => $node) {
  			if ($type == 'event' && $node['type'] == 'event' && $node['id'] == $att['id']) {
  				return $k;
  			}
  			if ($type == 'attribute' &&	$node['type'] == 'attribute' &&	$node['name'] == $att['value']) {
  				return $k;
  			}
  		}
  		return false;
  	}
  	public function graphJsonContainsLink($id1, $id2, $json) {
  		if (!isset($json['links'])) return false;
  		foreach ($json['links'] as $k => $link) {
  			if (($link['source'] == $id1 && $link['target'] == $id2) || ($link['source'] == $id2 && $link['target'] == $id1)) {
  				return $k;
  			}
  		}
  		return false;
  	}

  }
