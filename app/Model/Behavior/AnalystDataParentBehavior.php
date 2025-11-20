<?php

/**
 * Common functions for the 3 analyst objects
 */
class AnalystDataParentBehavior extends ModelBehavior
{
    private $__currentUser = null;
    private $__isRest = null;

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
        if (empty($this->__isRest)) {
            $this->__isRest = Configure::read('CurrentRequestIsRest');
        }

        $method = 'attach' . ($this->__isRest ? 'Flat' : 'Nested') . 'AnalystData';
        $fetchRecursive = !empty($model->includeAnalystDataRecursive);
        $data = $this->$method($object, $types, $fetchRecursive);

        // include inbound relationship
        $data['RelationshipInbound'] = Hash::extract($this->Relationship->getInboundRelationships($this->__currentUser, $model->alias, $object['uuid']), '{n}.Relationship');
        return $data;
    }

    private function attachFlatAnalystData(array $object, array $types, $fetchRecursive): array
    {
        $data = [];
        foreach ($types as $type) {
            $this->{$type} = ClassRegistry::init($type);
            $this->{$type}->fetchRecursive = $fetchRecursive;
            $temp = $this->{$type}->fetchForUuid($object['uuid'], $this->__currentUser);
            if (!empty($temp)) {
                foreach ($temp as $k => $temp_element) {
                    $data[$type][] = $temp_element[$type];
                    $childNotesAndOpinions = $this->{$type}->fetchChildNotesAndOpinions($this->__currentUser, $temp_element[$type], $this->__isRest);
                    if (!empty($childNotesAndOpinions)) {
                        foreach ($childNotesAndOpinions as $item) {
                            foreach ($item as $childType => $childElement) {
                                $data[$childType][] = $childElement;
                            }
                        }
                    }
                }
            }
        }
        return $data;
    }

    private function attachNestedAnalystData(array $object, array $types, $fetchRecursive): array
    {
        $data = [];
        foreach ($types as $type) {
            $this->{$type} = ClassRegistry::init($type);
            $this->{$type}->fetchRecursive = !empty($model->includeAnalystDataRecursive);
            $temp = $this->{$type}->fetchForUuid($object['uuid'], $this->__currentUser);
            if (!empty($temp)) {
                foreach ($temp as $k => $temp_element) {
                    if (in_array($type, ['Note', 'Opinion', 'Relationship'])) {
                        $temp_element[$type] = $this->{$type}->fetchChildNotesAndOpinions($this->__currentUser, $temp_element[$type], $this->__isRest, 5);
                    }
                    $data[$type][] = $temp_element[$type];
                }
            }
        }
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
                            foreach ($temp[$object['uuid']][$type] as $analystData) {
                                $objects[$chunk][$k][$type][] = $analystData;
                                $childNotesAndOpinions = $this->{$type}->fetchChildNotesAndOpinions($this->__currentUser, $analystData, $this->__isRest, 1);
                                if (!empty($childNotesAndOpinions)) {
                                    foreach ($childNotesAndOpinions as $item) {
                                        foreach ($item as $childType => $childElement) {
                                            $objects[$chunk][$k][$childType][] = $childElement;
                                        }
                                    }
                                }
                            }
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
