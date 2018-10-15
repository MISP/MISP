<?php
App::uses('AppModel', 'Model');
App::uses('RandomTool', 'Tools');

class Sighting extends AppModel
{
    public $useTable = 'sightings';

    public $recursive = -1;

    public $actsAs = array(
            'Containable',
    );

    public $validate = array(
        'event_id' => 'numeric',
        'attribute_id' => 'numeric',
        'org_id' => 'numeric',
        'date_sighting' => 'numeric',
        'type' => array(
            'rule' => array('inList', array(0, 1, 2)),
            'message' => 'Invalid type. Valid options are: 0 (Sighting), 1 (False-positive), 2 (Expiration).'
        )
    );

    public $belongsTo = array(
            'Attribute',
            'Event',
            'Organisation' => array(
                    'className' => 'Organisation',
                    'foreignKey' => 'org_id'
            ),
    );

    public $type = array(
        0 => 'sighting',
        1 => 'false-positive',
        2 => 'expiration'
    );

    public function beforeValidate($options = array())
    {
        parent::beforeValidate();
        $date = date('Y-m-d H:i:s');
        if (empty($this->data['Sighting']['id']) && empty($this->data['Sighting']['date_sighting'])) {
            $this->data['Sighting']['date_sighting'] = $date;
        }
        if (empty($this->data['Sighting']['uuid'])) {
            $this->data['Sighting']['uuid'] = CakeText::uuid();
        }
        return true;
    }

    public function afterSave($created, $options = array())
    {
        parent::afterSave($created, $options = array());
        if (Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_sighting_notifications_enable')) {
            $pubSubTool = $this->getPubSubTool();
            $user = array(
                'org_id' => -1,
                'Role' => array(
                    'perm_site_admin' => 1
                )
            );
            $sighting = $this->getSighting($this->id, $user);
            $pubSubTool->sighting_save($sighting, 'add');
        }
        return true;
    }

    public function beforeDelete($cascade = true)
    {
        parent::beforeDelete();
        if (Configure::read('Plugin.ZeroMQ_enable') && Configure::read('Plugin.ZeroMQ_sighting_notifications_enable')) {
            $pubSubTool = $this->getPubSubTool();
            $user = array(
                'org_id' => -1,
                'Role' => array(
                    'perm_site_admin' => 1
                )
            );
            $sighting = $this->getSighting($this->id, $user);
            $pubSubTool->sighting_save($sighting, 'delete');
        }
    }

    public function captureSighting($sighting, $attribute_id, $event_id, $user)
    {
        $org_id = 0;
        if (!empty($sighting['Organisation'])) {
            $org_id = $this->Organisation->captureOrg($sighting['Organisation'], $user);
        }
        if (isset($sighting['id'])) {
            unset($sighting['id']);
        }
        $sighting['org_id'] = $org_id;
        $sighting['event_id'] = $event_id;
        $sighting['attribute_id'] = $attribute_id;
        $this->create();
        return $this->save($sighting);
    }

    public function getSighting($id, $user)
    {
        $sighting = $this->find('first', array(
            'recursive' => -1,
            'contain' => array(
                'Attribute' => array(
                    'fields' => array('Attribute.value', 'Attribute.id', 'Attribute.uuid', 'Attribute.type', 'Attribute.category', 'Attribute.to_ids')
                ),
                'Event' => array(
                    'fields' => array('Event.id', 'Event.uuid', 'Event.orgc_id', 'Event.org_id', 'Event.info'),
                    'Orgc' => array(
                        'fields' => array('Orgc.name')
                    )
                )
            ),
            'conditions' => array('Sighting.id' => $id)
        ));
        if (empty($sighting)) {
            return array();
        }
        if ($user['Role']['perm_site_admin'] || $event['Event']['org_id'] == $user['org_id']) {
            $ownEvent = true;
        }
        if (!$ownEvent) {
            // if sighting policy == 0 then return false if the sighting doesn't belong to the user
            if (!Configure::read('Plugin.Sightings_policy') || Configure::read('Plugin.Sightings_policy') == 0) {
                if ($sighting['Sighting']['org_id'] != $user['org_id']) {
                    return array();
                }
            }
            // if sighting policy == 1, the user can only see the sighting if they've sighted something in the event once
            if (Configure::read('Plugin.Sightings_policy') == 1) {
                $temp = $this->find(
                    'first',
                    array(
                        'recursive' => -1,
                        'conditions' => array(
                            'Sighting.event_id' => $sighting['Sighting']['event_id'],
                            'Sighting.org_id' => $user['org_id']
                        )
                    )
                );
                if (empty($temp)) {
                    return array();
                }
            }
        }
        $anonymise = Configure::read('Plugin.Sightings_anonymise');
        if ($anonymise) {
            if ($sighting['Sighting']['org_id'] != $user['org_id']) {
                unset($sighting['Sighting']['org_id']);
                unset($sighting['Organisation']);
            }
        }
        // rearrange it to match the event format of fetchevent
        if (isset($sighting['Organisation'])) {
            $sighting['Sighting']['Organisation'] = $sighting['Organisation'];
            unset($sighting['Organisation']);
        }
        $result = array(
            'Sighting' => $sighting['Sighting']
        );
        $result['Sighting']['Event'] = $sighting['Event'];
        $result['Sighting']['Attribute'] = $sighting['Attribute'];
        if (!empty($sighting['Organisation'])) {
            $result['Sighting']['Organisation'] = $sighting['Organisation'];
        }
        return $result;
    }

    public function attachToEvent($event, $user = array(), $attribute_id = false, $extraConditions = false)
    {
        if (empty($user)) {
            $user = array(
                'org_id' => -1,
                'Role' => array(
                    'perm_site_admin' => 0
                )
            );
        }
        $ownEvent = false;
        if ($user['Role']['perm_site_admin'] || $event['Event']['org_id'] == $user['org_id']) {
            $ownEvent = true;
        }
        $conditions = array('Sighting.event_id' => $event['Event']['id']);
        if ($attribute_id) {
            $conditions[] = array('Sighting.attribute_id' => $attribute_id);
        }
        if (!$ownEvent && (!Configure::read('Plugin.Sightings_policy') || Configure::read('Plugin.Sightings_policy') == 0)) {
            $conditions['Sighting.org_id'] = $user['org_id'];
        }
        if ($extraConditions !== false) {
            $conditions['AND'] = $extraConditions;
        }
        $contain = array();
        if (Configure::read('MISP.showorg')) {
            $contain['Organisation'] = array('fields' => array('Organisation.id', 'Organisation.uuid', 'Organisation.name'));
        }

        // Sighting reporters setting
        // If the event has any sightings for the user's org, then the user is a sighting reporter for the event too.
        // This means that he /she has access to the sightings data contained within
        if (!$ownEvent && Configure::read('Plugin.Sightings_policy') == 1) {
            $temp = $this->find('first', array('recursive' => -1, 'conditions' => array('Sighting.event_id' => $event['Event']['id'], 'Sighting.org_id' => $user['org_id'])));
            if (empty($temp)) {
                return array();
            }
        }

        $sightings = $this->find('all', array(
                'conditions' => $conditions,
                'recursive' => -1,
                'contain' => $contain,
        ));
        if (empty($sightings)) {
            return array();
        }
        $anonymise = Configure::read('Plugin.Sightings_anonymise');

        foreach ($sightings as $k => $sighting) {
            if (
                $sighting['Sighting']['org_id'] == 0 && !empty($sighting['Organisation']) ||
                $anonymise
            ) {
                if ($sighting['Sighting']['org_id'] != $user['org_id']) {
                    unset($sightings[$k]['Sighting']['org_id']);
                    unset($sightings[$k]['Organisation']);
                }
            }
            // rearrange it to match the event format of fetchevent
            if (isset($sightings[$k]['Organisation'])) {
                $sightings[$k]['Sighting']['Organisation'] = $sightings[$k]['Organisation'];
            }
            // zeroq: add attribute UUID to sighting to make synchronization easier
            $attribute = $this->Attribute->fetchAttribute($sighting['Sighting']['attribute_id']);
            $sightings[$k]['Sighting']['attribute_uuid'] = $attribute['Attribute']['uuid'];

            $sightings[$k] = $sightings[$k]['Sighting'] ;
        }
        return $sightings;
    }

    public function saveSightings($id, $values, $timestamp, $user, $type = false, $source = false, $sighting_uuid = false)
    {
        $conditions = array();
        if ($id && $id !== 'stix') {
            $id = $this->explodeIdList($id);
            if (!is_array($id) && strlen($id) == 36) {
                $conditions = array('Attribute.uuid' => $id);
            } else {
                $conditions = array('Attribute.id' => $id);
            }
        } else {
            if (!$values) {
                return 'No valid attributes found.';
            }
            foreach ($values as $value) {
                foreach (array('value1', 'value2') as $field) {
                    $conditions['OR'][] = array(
                        'LOWER(Attribute.' . $field . ') LIKE' => strtolower($value)
                    );
                }
            }
        }
        if (!in_array($type, array(0, 1, 2))) {
            return 'Invalid type, please change it before you POST 1000000 sightings.';
        }
        $attributes = $this->Attribute->fetchAttributes($user, array('conditions' => $conditions, 'flatten' => 1));
        if (empty($attributes)) {
            return 'No valid attributes found that match the criteria.';
        }
        $sightingsAdded = 0;
        foreach ($attributes as $attribute) {
            if ($type === '2') {
                // remove existing expiration by the same org if it exists
                $this->deleteAll(array('Sighting.org_id' => $user['org_id'], 'Sighting.type' => $type, 'Sighting.attribute_id' => $attribute['Attribute']['id']));
            }
            $this->create();
            $sighting = array(
                    'attribute_id' => $attribute['Attribute']['id'],
                    'event_id' => $attribute['Attribute']['event_id'],
                    'org_id' => $user['org_id'],
                    'date_sighting' => $timestamp,
                    'type' => $type,
                    'source' => $source
            );
            // zeroq: allow setting a specific uuid
            if($sighting_uuid) {
                $sighting['uuid'] = $sighting_uuid;
                // check if sighting with given uuid already exists
                $existing_sighting = $this->find('first', array(
                    'recursive' => -1,
                    'conditions' => array('uuid' => $sighting_uuid)
                ));
                // do not add sighting if already exists
                if (!empty($existing_sighting)) {
                    return 0;
                }
            }
            $result = $this->save($sighting);
            if ($result === false) {
                return json_encode($this->validationErrors);
            }
            $sightingsAdded += $result ? 1 : 0;
        }
        if ($sightingsAdded == 0) {
            return 'There was nothing to add.';
        }
        return $sightingsAdded;
    }

    public function handleStixSighting($data)
    {
        $randomFileName = $this->generateRandomFileName();
        $tempFile = new File(APP . "files" . DS . "scripts" . DS . "tmp" . DS . $randomFileName, true, 0644);

        // save the json_encoded event(s) to the temporary file
        if (!$tempFile->write($data)) {
            return array('success' => 0, 'message' => 'Could not write the Sightings file to disk.');
        }
        $tempFile->close();
        $scriptFile = APP . "files" . DS . "scripts" . DS . "stixsighting2misp.py";
        // Execute the python script and point it to the temporary filename
        $result = shell_exec('python3 ' . $scriptFile . ' ' . $randomFileName);
        // The result of the script will be a returned JSON object with 2 variables: success (boolean) and message
        // If success = 1 then the temporary output file was successfully written, otherwise an error message is passed along
        $result = json_decode($result, true);

        if ($result['success'] == 1) {
            $file = new File(APP . "files" . DS . "scripts" . DS . "tmp" . DS . $randomFileName . ".out");
            $result['data'] = $file->read();
            $file->close();
            $file->delete();
        }
        $tempFile->delete();
        return $result;
    }

    public function generateRandomFileName()
    {
        return (new RandomTool())->random_str(false, 12);
    }

    public function addUuids()
    {
        $sightings = $this->find('all', array(
            'recursive' => -1,
            'conditions' => array('uuid' => '')
        ));
        $this->saveMany($sightings);
        return true;
    }

    public function explodeIdList($id)
    {
        if (strpos($id, '|')) {
            $id = explode('|', $id);
            foreach ($id as $k => $v) {
                if (!is_numeric($v)) {
                    unset($id[$k]);
                }
            }
            $id = array_values($id);
        }
        return $id;
    }

    public function getSightingsForTag($user, $tag_id, $sgids = array(), $type = false)
    {
        $range = (!empty(Configure::read('MISP.Sightings_range')) && is_numeric(Configure::read('MISP.Sightings_range'))) ? Configure::read('MISP.Sightings_range') : 365;
        $conditions = array(
            'Sighting.date_sighting >' => strtotime("-" . $range . " days"),
            'EventTag.tag_id' => $tag_id
        );
        if ($type !== false) {
            $conditions['Sighting.type'] = $type;
        }
        $this->bindModel(
            array(
                'hasOne' => array(
                    'EventTag' => array(
                        'className' => 'EventTag',
                        'foreignKey' => false,
                        'conditions' => 'EventTag.event_id = Sighting.event_id'
                    )
                )
            )
        );
        $sightings = $this->find('all', array(
            'recursive' => -1,
            'contain' => array('EventTag'),
            'conditions' => $conditions,
            'fields' => array('Sighting.id', 'Sighting.event_id', 'Sighting.date_sighting', 'EventTag.tag_id')
        ));
        $sightingsRearranged = array();
        foreach ($sightings as $sighting) {
            $date = date("Y-m-d", $sighting['Sighting']['date_sighting']);
            if (isset($sightingsRearranged[$date])) {
                $sightingsRearranged[$date]++;
            } else {
                $sightingsRearranged[$date] = 1;
            }
        }
        return $sightingsRearranged;
    }

    public function getSightingsForObjectIds($user, $tagList, $context = 'event', $type = '0')
    {
        $range = (!empty(Configure::read('MISP.Sightings_range')) && is_numeric(Configure::read('MISP.Sightings_range'))) ? Configure::read('MISP.Sightings_range') : 365;
        $conditions = array(
            'Sighting.date_sighting >' => strtotime("-" . $range . " days"),
            ucfirst($context) . 'Tag.tag_id' => $tagList

        );
        $contain = array(
            ucfirst($context) => array(
                ucfirst($context) . 'Tag' => array(
                    'Tag'
                )
            )
        );
        if ($type !== false) {
            $conditions['Sighting.type'] = $type;
        }
        $this->bindModel(array('hasOne' => array(ucfirst($context) . 'Tag' => array('foreignKey' => false, 'conditions' => ucfirst($context) . 'Tag.' . $context . '_id = Sighting.' . $context . '_id'))));
        $sightings = $this->find('all', array(
            'recursive' => -1,
            'contain' => array(ucfirst($context) . 'Tag'),
            'conditions' => $conditions,
            'fields' => array('Sighting.id', 'Sighting.' . $context . '_id', 'Sighting.date_sighting', ucfirst($context) . 'Tag.tag_id')
        ));
        $sightingsRearranged = array();
        foreach ($sightings as $sighting) {
            $date = date("Y-m-d", $sighting['Sighting']['date_sighting']);
            if (isset($sightingsRearranged[$sighting['Sighting'][$context . '_id']][$date])) {
                $sightingsRearranged[$sighting['Sighting'][$context . '_id']][$date]++;
            } else {
                $sightingsRearranged[$sighting['Sighting'][$context . '_id']][$date] = 1;
            }
        }
        return $sightingsRearranged;
    }
}
