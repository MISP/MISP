<?php

class AttackSightingsExport
{
    public $additional_params = array(
        'includeEventTags' => 1,
        'includeGalaxy' => 1,
        'includeSightings' => 1
    );
    public $non_restrictive_export = true;

    private $__sightingType = 'direct-technique-sighting';
    private $__detectionType = 'raw';

    private $__attribute_sightings = array();
    private $__sightings = array();
    private $__galaxyType = 'mitre-attack-pattern';
    private $__event_id = null;
    private $__tag_ids = array();

    public function handler($data, $options = array())
    {
        if ($options['scope'] === 'Attribute') {
            return $this->__attributeHandler($data);
        } else if ($options['scope'] === 'Event') {
            return $this->__eventHandler($data);
        }
    }

    private function __attributeHandler($attribute)
    {
        $attribute = array_merge($attribute['Attribute'], $attribute);
        unset($attribute['Attribute']);
        $this->__parse_attribute($attribute);
        return '';
    }

    private function __eventHandler($event)
    {
        if (!empty($event['Sighting'])) {
            foreach($event['Sighting'] as $sighting) {
                $attribute_uuid = $sighting['attribute_uuid'];
                if (empty($this->__attribute_sightings[$attribute_uuid])) {
                    $this->__attribute_sightings[$attribute_uuid] = array($sighting['date_sighting']);
                } else {
                    $this->__attribute_sightings[$attribute_uuid][] = $sighting['date_sighting'];
                }
            }
        }
        if (!empty($event['Galaxy'])) {
            foreach($event['Galaxy'] as $galaxy) {
                if ($galaxy['type'] === $this->__galaxyType) {
                    $this->__parse_galaxy($event['Event'], $galaxy['GalaxyCluster']);
                }
            }
        }
        if (!empty($event['Object'])) {
            foreach($event['Object'] as $object) {
                if (!empty($object['Attribute'])) {
                    foreach($object['Attribute'] as $attribute) {
                        $this->__parse_attribute($attribute);
                    }
                }
            }
        }
        if (!empty($event['Attribute'])) {
            foreach($event['Attribute'] as $attribute) {
                $this->__parse_attribute($attribute);
            }
        }
        return '';
    }

    private function __aggregate($techniques, $startTime, $endTime, $uuid)
    {
        $sighting = array(
            'id' => $uuid,
            'sightingType' => $this->__sightingType,
            'startTime' => $startTime,
            'endTime' => $endTime,
            'detectionType' => $this->__detectionType,
            'techniques' => $techniques
        );
        $this->__sightings[] = $sighting;
    }

    private function __parse_attribute($attribute)
    {
        if (!empty($attribute['Galaxy'])) {
            if (!empty($attribute['EventTag'])) {
                if ($attribute['event_id'] != $this->__event_id) {
                    $this->__event_id = $attribute['event_id'];
                    foreach($attribute['EventTag'] as $event_tag) {
                        if (!in_array($event_tag['tag_id'], $this->__tag_ids)) {
                            $this->__tag_ids[] = $event_tag['tag_id'];
                        }
                    }
                }
            }
            foreach($attribute['Galaxy'] as $galaxy) {
                if ($galaxy['type'] === $this->__galaxyType) {
                    $this->__parse_galaxy($attribute, $galaxy['GalaxyCluster']);
                }
            }
        }
    }

    private function __parse_galaxy($object, $clusters)
    {
        $techniques = array();
        foreach($clusters as $cluster) {
            if (!in_array($cluster['tag_id'], $this->__tag_ids)) {
                $techniques[] = array('techniqueID' => trim(explode(" - ", $cluster['value'])[1], '"'));
            }
        }
        if (!empty($techniques)) {
            $timestamps = array((int)$object['timestamp']);
            if (!empty($object['Sighting'])) {
                foreach($object['Sighting'] as $sighting) {
                    $timestamps[] = (int)$sighting['date_sighting'];
                }
            } else if (!empty($this->__attribute_sightings[$object['uuid']])) {
                $timestamps = array_merge($this->__attribute_sightings[$object['uuid']], $timestamps);
            }
            $startTime = $this->__parse_timestamp(min($timestamps));
            $endTime = $this->__parse_timestamp(max($timestamps));
            $this->__aggregate($techniques, $startTime, $endTime, $object['uuid']);
        }
    }

    private function __parse_timestamp($timestamp)
    {
        $date = new DateTime();
        $date->setTimestamp((int)$timestamp);
        return $date->format('Y-m-d') . 'T' . $date->format('H:i:s') . 'Z';
    }

    public function header($options = array())
    {
        return '';
    }

    public function footer()
    {
        return json_encode($this->__sightings);
    }

    public function separator()
    {
        return '';
    }
}
