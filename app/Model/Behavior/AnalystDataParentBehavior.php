<?php

/**
 * Common functions for the 3 analyst objects
 */
class AnalystDataParentBehavior extends ModelBehavior
{
    private $__currentUser = null;

    public $User;



    public function attachAnalystData(Model $model, array $object, array $types = ['Note', 'Opinion', 'Relationship'])
    {
        // No uuid, nothing to attach
        if (empty($object['uuid'])) {
            return $object;
        }
        if (empty($this->__currentUser)) {
            $user_id = Configure::read('CurrentUserId');
            $this->User = ClassRegistry::init('User');
            if ($user_id) {
                $this->__currentUser = $this->User->getAuthUser($user_id);
            }
        }
        $data = [];
        foreach ($types as $type) {
            $this->{$type} = ClassRegistry::init($type);
            $this->{$type}->fetchRecursive = !empty($model->includeAnalystDataRecursive);
            $temp = $this->{$type}->fetchForUuid($object['uuid'], $this->__currentUser);
            if (!empty($temp)) {
                foreach ($temp as $k => $temp_element) {
                    if (in_array($type, ['Note', 'Opinion', 'Relationship'])) {
                        $temp_element[$type] = $this->{$type}->fetchChildNotesAndOpinions($this->__currentUser, $temp_element[$type], 1);
                    }
                    $data[$type][] = $temp_element[$type];
                }
            }
        }

        // include inbound relationship
        $data['RelationshipInbound'] = Hash::extract($this->Relationship->getInboundRelationships($this->__currentUser, $model->alias, $object['uuid']), '{n}.Relationship');
        return $data;
    }

    public function fetchAnalystDataBulk(Model $model, array $uuids, array $types = ['Note', 'Opinion', 'Relationship']) {
        $uuids = array_chunk($uuids, 100000);
        if (empty($this->__currentUser)) {
            $user_id = Configure::read('CurrentUserId');
            $this->User = ClassRegistry::init('User');
            if ($user_id) {
                $this->__currentUser = $this->User->getAuthUser($user_id);
            }
        }
        $results = [];
        foreach ($uuids as $uuid_chunk) {
            foreach ($types as $type) {
                $this->{$type} = ClassRegistry::init($type);
                $this->{$type}->fetchRecursive = !empty($model->includeAnalystDataRecursive);
                $temp = $this->{$type}->fetchForUuids($uuid_chunk, $this->__currentUser);
                $results = array_merge_recursive($results, $temp);
            }
        }
        return $results;
    }

    public function attachAnalystDataBulk(Model $model, array $objects, array $types = ['Note', 'Opinion', 'Relationship'])
    {
        $uuids = [];
        $objects = array_chunk($objects, 100000, true);
        if (empty($this->__currentUser)) {
            $user_id = Configure::read('CurrentUserId');
            $this->User = ClassRegistry::init('User');
            if ($user_id) {
                $this->__currentUser = $this->User->getAuthUser($user_id);
            }
        }
        foreach ($objects as $chunk => $chunked_objects) {
            foreach ($chunked_objects as $k => $object) {
                if (!empty($object['uuid'])) {
                    $uuids[] = $object['uuid'];
                }
            }
            // No uuids, nothing to attach
            if (empty($uuids)) {
                continue;
            }
            foreach ($types as $type) {
                $this->{$type} = ClassRegistry::init($type);
                $this->{$type}->fetchRecursive = !empty($model->includeAnalystDataRecursive);
                $temp = $this->{$type}->fetchForUuids($uuids, $this->__currentUser);
                if (!empty($temp)) {
                    foreach ($chunked_objects as $k => $object) {
                        if (!empty($temp[$object['uuid']])) {
                            $objects[$chunk][$k][$type] = !empty($objects[$chunk][$k][$type]) ? $objects[$chunk][$k][$type] : [];
                            $objects[$chunk][$k][$type] = array_merge($objects[$chunk][$k][$type], $temp[$object['uuid']][$type]);
                        }
                    }
                }
            }
        }
        $objects = call_user_func_array('array_merge', $objects);
        return $objects;
    }

    public function afterFind(Model $model, $results, $primary = false)
    {
        if (!empty($model->includeAnalystData)) {
            foreach ($results as $k => $item) {
                if (isset($item[$model->alias])) {
                    $results[$k] = array_merge($results[$k], $this->attachAnalystData($model, $item[$model->alias]));
                }
            }
        }
        return $results;
    }

}
