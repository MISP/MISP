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
                    $data[$type][] = $temp_element[$type];
                }
            }
        }
        return $data;
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
