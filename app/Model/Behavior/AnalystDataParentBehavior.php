<?php

/**
 * Common functions for the 3 analyst objects
 */
class AnalystDataParentBehavior extends ModelBehavior
{
    private $__currentUser = null;
    private $__isRest = null;

    public $User;



    public function attachAnalystData(Model $model, array $object, array $types = ['Note', 'Opinion', 'Relationship'], $prefetched = null, $prefetchedInbound = null)
    {
        // No uuid, nothing to attach
        if (empty($object['uuid'])) {
            return $object;
        }
        $this->__setContext();

        $method = 'attach' . ($this->__isRest ? 'Flat' : 'Nested') . 'AnalystData';
        $fetchRecursive = !empty($model->includeAnalystDataRecursive);
        $data = $this->$method($object, $types, $fetchRecursive, $prefetched);

        // include inbound relationship
        if ($prefetchedInbound === null) {
            $inbound = $this->Relationship->getInboundRelationships($this->__currentUser, $model->alias, $object['uuid']);
        } else {
            $inbound = isset($prefetchedInbound[$object['uuid']]) ? $prefetchedInbound[$object['uuid']] : [];
            if ($this->__isRest && $fetchRecursive) {
                // The batched inbound query ran with the recursion disabled - replay it here so the
                // fetchedUUIDFromRecursion memo is written in the same order as the per-row path.
                $this->Relationship = ClassRegistry::init('Relationship');
                foreach ($inbound as $i => $relationship) {
                    $inbound[$i]['Relationship'] = $this->__fetchChildrenFor('Relationship', $relationship['Relationship']);
                }
            }
        }
        $data['RelationshipInbound'] = Hash::extract($inbound, '{n}.Relationship');
        return $data;
    }

    private function __setContext()
    {
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
    }

    private function attachFlatAnalystData(array $object, array $types, $fetchRecursive, $prefetched = null): array
    {
        $data = [];
        foreach ($types as $type) {
            $this->{$type} = ClassRegistry::init($type);
            $this->{$type}->fetchRecursive = $fetchRecursive;
            $temp = $this->__elementsForUuid($type, $object['uuid'], $prefetched, $fetchRecursive);
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

    private function attachNestedAnalystData(array $object, array $types, $fetchRecursive, $prefetched = null): array
    {
        $data = [];
        foreach ($types as $type) {
            $this->{$type} = ClassRegistry::init($type);
            // The nested path does its own depth-5 recursion below, so afterFind() must not also
            // recurse - it would memoise the uuids in fetchedUUIDFromRecursion and make the
            // deeper call below short-circuit. Reset explicitly: the model is a registry
            // singleton and may still be flagged from an earlier fetch in this request.
            $this->{$type}->fetchRecursive = false;
            $temp = $this->__elementsForUuid($type, $object['uuid'], $prefetched, false);
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

    /**
     * Return the analyst data elements of a given type for a single uuid, in the row shape
     * fetchForUuid() produces ([['Note' => [...]], ...]). When $prefetched is provided the rows
     * come from the batched fetch instead of a dedicated query.
     */
    private function __elementsForUuid($type, $uuid, $prefetched, $fetchRecursive)
    {
        if ($prefetched === null) {
            return $this->{$type}->fetchForUuid($uuid, $this->__currentUser);
        }
        if (empty($prefetched[$type][$uuid])) {
            return [];
        }
        // Copy: the recursed shape must never be written back into the prefetch cache, so that a
        // uuid appearing on two rows behaves exactly like two separate fetchForUuid() calls.
        $elements = $prefetched[$type][$uuid];
        $rows = [];
        foreach ($elements as $element) {
            if ($fetchRecursive) {
                $element = $this->__fetchChildrenFor($type, $element);
            }
            $rows[] = [$type => $element];
        }
        return $rows;
    }

    /**
     * Replay of the recursion block of AnalystData::afterFind() (AnalystData.php:172-179) for one
     * prefetched element. The batched queries deliberately run with fetchRecursive disabled: that
     * block writes to AnalystData::$fetchedUUIDFromRecursion, a per-model memo that is never reset,
     * and which decides whether a given analyst element carries its nested children or only
     * '_max_depth_reached'. Hoisting the queries is safe, hoisting that memo write is not - the same
     * Relationship row is reachable both outbound (object_uuid) and inbound (related_object_uuid),
     * so whichever sighting comes first wins. Running the recursion here, from the per-row loop,
     * keeps the memo write order byte-identical to the unbatched path.
     */
    private function __fetchChildrenFor($type, array $element): array
    {
        $Note = ClassRegistry::init('Note');
        $Opinion = ClassRegistry::init('Opinion');
        $Note->fetchRecursive = false;
        $Opinion->fetchRecursive = false;
        // Relationship::afterFind() appends related_object AFTER parent::afterFind() has appended
        // the recursion keys. The batched find ran the two in the opposite order, so re-append it
        // here to keep the key order (and therefore the serialised JSON) identical.
        $hasRelated = array_key_exists('related_object', $element);
        if ($hasRelated) {
            $related = $element['related_object'];
            unset($element['related_object']);
        }
        $user = $this->{$type}->current_user ?? $this->__currentUser;
        $element = $this->{$type}->fetchChildNotesAndOpinions($user, $element, false);
        if ($hasRelated) {
            $element['related_object'] = $related;
        }
        $Note->fetchRecursive = true;
        $Opinion->fetchRecursive = true;
        return $element;
    }

    /**
     * Batched equivalent of the per-uuid fetchForUuid() calls done by attach*AnalystData():
     * one IN-list query per type instead of one query per type per row. The IN-list is chunked at
     * 1000 like the other bulk helpers in this file. The caller owns the fetchRecursive flag.
     * Returns [type][object_uuid] => list of elements.
     */
    private function __prefetchAnalystData(Model $model, array $uuids, array $types)
    {
        $prefetched = [];
        foreach ($types as $type) {
            $prefetched[$type] = [];
        }
        foreach (array_chunk($uuids, 1000) as $uuid_chunk) {
            foreach ($types as $type) {
                $temp = $this->{$type}->fetchForUuids($uuid_chunk, $this->__currentUser);
                foreach ($temp as $uuid => $elementsByType) {
                    if (!empty($elementsByType[$type])) {
                        $prefetched[$type][$uuid] = $elementsByType[$type];
                    }
                }
            }
        }
        return $prefetched;
    }

    public function fetchAnalystDataBulk(Model $model, array $uuids, array $types = ['Note', 'Opinion', 'Relationship']) {
        // Keep the per-query IN-list bounded so the optimizer stays on the object_uuid index
        // and parse cost stays low. 1000 is comfortable for MySQL/MariaDB defaults.
        $uuids = array_chunk($uuids, 1000);
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
        // Keep the per-query IN-list bounded so the optimizer stays on the object_uuid index
        // and parse cost stays low. 1000 is comfortable for MySQL/MariaDB defaults.
        $objects = array_chunk($objects, 1000, true);
        if (empty($this->__currentUser)) {
            $user_id = Configure::read('CurrentUserId');
            $this->User = ClassRegistry::init('User');
            if ($user_id) {
                $this->__currentUser = $this->User->getAuthUser($user_id);
            }
        }
        foreach ($objects as $chunk => $chunked_objects) {
            // Reset per chunk — previously $uuids was declared outside the loop and accumulated
            // across iterations, growing the IN list on every chunk.
            $uuids = [];
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
                                // Always request the flat (REST-shaped) child list: to flatten children into sibling arrays 
                                $childNotesAndOpinions = $this->{$type}->fetchChildNotesAndOpinions($this->__currentUser, $analystData, true, 1);
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
            $types = ['Note', 'Opinion', 'Relationship'];
            $prefetched = null;
            $prefetchedInbound = null;
            $uuids = [];
            foreach ($results as $item) {
                if (isset($item[$model->alias]) && !empty($item[$model->alias]['uuid'])) {
                    $uuids[$item[$model->alias]['uuid']] = true;
                }
            }
            // With more than one row the per-row attach costs 4 queries per row (3 fetchForUuid +
            // 1 inbound relationship lookup). Batch them into 4 IN-list queries for the whole set
            // and hand the results to attachAnalystData(), which keeps the per-row shape untouched.
            if (count($uuids) > 1) {
                $this->__setContext();
                $uuids = array_keys($uuids);
                // The batched finds must not trigger AnalystData::afterFind()'s recursion: it writes
                // to a never-reset per-model memo whose order decides which sighting of an element
                // keeps its children. attach*AnalystData() replays that recursion per row instead.
                foreach ($types as $type) {
                    $this->{$type} = ClassRegistry::init($type);
                    $this->{$type}->fetchRecursive = false;
                }
                $prefetched = $this->__prefetchAnalystData($model, $uuids, $types);
                $this->Relationship = ClassRegistry::init('Relationship');
                $prefetchedInbound = [];
                foreach (array_chunk($uuids, 1000) as $uuid_chunk) {
                    $prefetchedInbound += $this->Relationship->getInboundRelationshipsBulk($this->__currentUser, $model->alias, $uuid_chunk);
                }
                // Leave the flag exactly as the per-row path would have left it.
                $restore = $this->__isRest ? !empty($model->includeAnalystDataRecursive) : false;
                foreach ($types as $type) {
                    $this->{$type}->fetchRecursive = $restore;
                }
            }
            foreach ($results as $k => $item) {
                if (isset($item[$model->alias])) {
                    $results[$k] = array_merge($results[$k], $this->attachAnalystData($model, $item[$model->alias], $types, $prefetched, $prefetchedInbound));
                }
            }
        }
        return $results;
    }

}
