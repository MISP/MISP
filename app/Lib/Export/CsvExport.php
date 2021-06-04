<?php

class CsvExport
{
	public $event_context_fields = array('event_info', 'event_member_org', 'event_source_org', 'event_distribution', 'event_threat_level_id', 'event_analysis', 'event_date', 'event_tag', 'event_timestamp');
	public $default_fields = array('uuid', 'event_id', 'category', 'type', 'value', 'comment', 'to_ids', 'timestamp', 'object_relation', 'attribute_tag');
	public $default_obj_fields = array('object_uuid', 'object_name', 'object_meta-category');
	public $requested_fields = array();
	public $decaying_fields = array('decay_score_score', 'decay_score_decayed');
	public $non_restrictive_export = true;

    public function handler($data, $options = array())
    {
		if ($options['scope'] === 'Attribute') {
			$lines = $this->__attributesHandler($data, $options);
		} else if($options['scope'] === 'Event') {
			$lines = $this->__eventsHandler($data, $options);
		} else if($options['scope'] === 'Sighting') {
			$lines = $this->__sightingsHandler($data, $options);
		}
        return $lines;
    }

	public function modify_params($user, $params)
	{
		if (!empty($params['includeDecayScore'])) {
			$this->enable_decaying();
		}
		if (empty($params['contain'])) {
			$params['contain'] = array();
		}
		$params['contain'] = array_merge($params['contain'], array(
			'Object' => array('fields' => array('Object.uuid', 'Object.name', 'Object.meta-category')),
			'AttributeTag' => array('Tag'),
			'Event' => array('fields' => array('Event.*'), 'EventTag' => 'Tag', 'Org.name', 'Orgc.name', 'ThreatLevel')
		));
		unset($params['fields']);
		$params['withAttachments'] = 0;
		$params['includeContext'] = 0; // Needed as fetchAttributes override the Event entry
		return $params;
	}

	public function enable_decaying()
	{
		$this->default_fields = array_merge($this->default_fields, $this->decaying_fields);
	}

	private function __attributesHandler($attribute, $options)
	{
		$attribute = $this->__addMetadataToAttributeAtomic($attribute);
		if (!empty($attribute['Object']['uuid'])) {
			$attribute['object_uuid'] = $attribute['Object']['uuid'];
			$attribute['object_name'] = $attribute['Object']['name'];
			$attribute['object_meta-category'] = $attribute['Object']['meta-category'];
		}
		if (!empty($attribute['decay_score'])) {
			$all_scores = Hash::extract($attribute, 'decay_score.{n}.score');
			$all_decayed = Hash::extract($attribute, 'decay_score.{n}.decayed');
			$avg_score = array_sum($all_scores)/count($all_scores);
			$avg_decayed = count(array_intersect([true], $all_decayed)) > 0;
			$attribute['decay_score_score'] = $avg_score;
			$attribute['decay_score_decayed'] = $avg_decayed;
		} else {
			$attribute['decay_score_score'] = 0;
			$attribute['decay_score_decayed'] = false;
		}
		return $this->__addLine($attribute, $options);
	}

        private function __sightingsHandler($sighting, $options)
        {
                $lines = '';
                if (isset($sighting['Sighting']['Event'])) {
                    foreach($sighting['Sighting']['Event'] as $k => $event_val) {
                        $new_key = 'event_' . $k;
                        // in case we have an array, e.g. orc => name
                        if (is_array($event_val)) {
                            $v2 = reset($event_val);
                            $k2 = key($event_val);
                            $new_key .= '_' . $k2;
                            $event_val = $v2;
                        }
                        $sighting['Sighting'][$new_key] = $event_val;
                    }
                }
                if (isset($sighting['Sighting']['Attribute'])) {
                    foreach($sighting['Sighting']['Attribute'] as $k => $attribute_val) {
                        $new_key = 'attribute_' . $k;
                        $sighting['Sighting'][$new_key] = $attribute_val;
                    }
                }
		$lines .= $this->__addLine($sighting['Sighting'], $options);
                return $lines;
	}

	private function __eventsHandler($event, $options)
	{
		$lines = '';
		if (!empty($event['Attribute'])) {
			foreach ($event['Attribute'] as $k => $attribute) {
				$attribute = $this->__addMetadataToAttribute($event, $attribute);
				$lines .= $this->__addLine($attribute, $options);
			}
		}
		if (!empty($event['Object'])) {
			foreach ($event['Object'] as $k => $object) {
				if (!empty($object['Attribute'])) {
					foreach ($object['Attribute'] as $attribute) {
						$attribute = $this->__addMetadataToAttribute($event, $attribute);
						$attribute['object_uuid'] = $object['uuid'];
						$attribute['object_name'] = $object['name'];
						$attribute['object_meta-category'] = $object['meta-category'];
						$lines .= $this->__addLine($attribute, $options);
					}
				}
			}
		}
		return $lines;
	}

	private function __addLine($attribute, $options = array()) {
		$line = '';
		foreach ($this->requested_fields as $req_att) {
			if (empty($line)) {
				$line = $this->__escapeCSVField($attribute[$req_att]);
			} else {
				$line .= ',' . $this->__escapeCSVField($attribute[$req_att]);
			}
		}
		return $line . PHP_EOL;
	}

	private function __escapeCSVField(&$field)
	{
		if (is_bool($field)) {
			return ($field ? '1' : '0');
		}
		if (is_numeric($field)) {
			return $field;
		}
		$field = str_replace(array('"'), '""', $field);
		$field = '"' . $field . '"';
		return $field;
	}

	private function __addMetadataToAttributeAtomic($attribute_raw) {
		$attribute = $attribute_raw['Attribute'];
		if (!empty($attribute_raw['AttributeTag'])) {
			$tags = array();
			foreach ($attribute_raw['AttributeTag'] as $at) {
				$tags[] = $at['Tag']['name'];
			}
			$tags = implode(',', $tags);
			$attribute['attribute_tag'] = $tags;
		}
		$attribute['event_info'] = $attribute_raw['Event']['info'];
		$attribute['event_member_org'] = $attribute_raw['Event']['Org']['name'];
		$attribute['event_source_org'] = $attribute_raw['Event']['Orgc']['name'];
		$attribute['event_distribution'] = $attribute_raw['Event']['distribution'];
		$attribute['event_threat_level_id'] = $attribute_raw['Event']['ThreatLevel']['name'];
		$attribute['event_analysis'] = $attribute_raw['Event']['analysis'];
		$attribute['event_date'] = $attribute_raw['Event']['date'];
		$attribute['event_timestamp'] = $attribute_raw['Event']['timestamp'];
		if (!empty($attribute_raw['Event']['EventTag'])) {
			$tags = array();
			foreach ($attribute_raw['Event']['EventTag'] as $et) {
				$tags[] = $et['Tag']['name'];
			}
			$tags = implode(',', $tags);
			$attribute['event_tag'] = $tags;
		}
		return $attribute;
	}

	private function __addMetadataToAttribute($event, $attribute) {
		if (!empty($attribute['AttributeTag'])) {
			$tags = array();
			foreach ($attribute['AttributeTag'] as $at) {
				$tags[] = $at['Tag']['name'];
			}
			$tags = implode(',', $tags);
			$attribute['attribute_tag'] = $tags;
		}
		$attribute['event_info'] = $event['Event']['info'];
		$attribute['event_member_org'] = $event['Org']['name'];
		$attribute['event_source_org'] = $event['Orgc']['name'];
		$attribute['event_distribution'] = $event['Event']['distribution'];
		$attribute['event_threat_level_id'] = $event['ThreatLevel']['name'];
		$attribute['event_analysis'] = $event['Event']['analysis'];
		$attribute['event_date'] = $event['Event']['date'];
		$attribute['event_timestamp'] = $event['Event']['timestamp'];
		if (!empty($event['EventTag'])) {
			$tags = array();
			foreach ($event['EventTag'] as $et) {
				$tags[] = $et['Tag']['name'];
			}
			$tags = implode(',', $tags);
			$attribute['event_tag'] = $tags;
		}
		return $attribute;
	}

    public function header(&$options)
    {
		if (isset($options['filters']['requested_attributes'])) {
			$this->requested_fields = $options['filters']['requested_attributes'];
		} else {
			$this->requested_fields = $this->default_fields;
		}
		if (isset($options['filters']['requested_obj_attributes'])) {
			$requested_obj_attributes = array();
			foreach ($options['filters']['requested_obj_attributes'] as $roa) {
				$requested_obj_attributes[] = 'object_' . $roa;
			}
		} else {
			if (isset($options['filters']['requested_attributes'])) {
				$requested_obj_attributes = array();
			} else {
				$requested_obj_attributes = $this->default_obj_fields;
			}
		}
		foreach ($requested_obj_attributes as $obj_att) {
			$this->requested_fields[] = $obj_att;
		}
		if (!empty($options['filters']['includeContext'])) {
			foreach ($this->event_context_fields as $event_context_field) {
				$this->requested_fields[] = $event_context_field;
			}
		}
		$object_level_search = false;
        foreach ($this->requested_fields as $k => $v) {
			if (in_array($v, $this->default_obj_fields)) {
				$object_level_search = true;
			}
            $headers[$k] = str_replace('-', '_', $v);
            if ($v == 'timestamp') {
                $headers[$k] = 'date';
            }
        }
		if (!$object_level_search) {
			$options['flatten'] = 1;
		}
        $headers = implode(',', $headers) . PHP_EOL;
        if (!empty($options['filters']['headerless'])) {
            return '';
        }
        return $headers;
    }

    public function footer()
    {
        return PHP_EOL;
    }

    public function separator()
    {
        return '';
    }

	public function eventIndex($events)
	{
		$fields = array(
			'id', 'date', 'info', 'tags', 'uuid', 'published', 'analysis', 'attribute_count', 'orgc_id', 'orgc_name', 'orgc_uuid', 'timestamp', 'distribution', 'sharing_group_id', 'threat_level_id',
			'publish_timestamp', 'extends_uuid'
		);
		$result = implode(',', $fields) . PHP_EOL;
		foreach ($events as $key => $event) {
			$event['tags'] = '';
			if (!empty($event['EventTag'])) {
				$tags = array();
				foreach ($event['EventTag'] as $et) {
					$tags[] = $et['Tag']['name'];
				}
				$tags = implode(', ', $tags);
			} else {
				$tags = '';
			}
			$event['Event']['tags'] = $tags;
			$event['Event']['orgc_name'] = $event['Orgc']['name'];
			$event['Event']['orgc_uuid'] = $event['Orgc']['uuid'];
			$current = array();
			foreach ($fields as $field) {
				$current[] = $this->__escapeCSVField($event['Event'][$field]);
			}
			$result .= implode(', ', $current) . PHP_EOL;
		}
		return $result;
	}

}
