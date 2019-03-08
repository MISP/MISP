<?php

App::uses('AppModel', 'Model');

class DecayingModel extends AppModel
{
    public $actsAs = array('Containable');

    public $hasMany = array(
    );

    public function afterFind($results, $primary = false) {
        foreach ($results as $k => $v) {
            if (!empty($v['DecayingModel']['parameters'])) {
                $decoded = json_decode($v['DecayingModel']['parameters'], true);
                if ($decoded === null) {
                    $decoded = array();
                }
                $results[$k]['DecayingModel']['parameters'] = $decoded;
            }
        }
        return $results;
    }

    public function beforeValidate($options = array()) {
        if (!empty($this->data['DecayingModel']['parameters'])) {
            $encoded = json_decode($this->data['DecayingModel']['parameters'], true);
            if ($encoded !== null) {
                return true;
            }
            return false;
        }
    }

    public function fetchAllowedModels($user) {
        $conditions = array();
        if (!$user['Role']['perm_site_admin']) {
            if ($user['Role']['perm_decaying']) {
                $conditions['org_id'] = $user['Organisation']['id'];
            } else {
                return array();
            }
        }
        $decayingModel = $this->find('all', array(
            'conditions' => $conditions,
            'recursive' => -1,
        ));

        return $decayingModel;
    }

    public function checkAuthorisation($user, $id) {
        // fetch the bare template
        $decayingModel = $this->find('first', array(
            'conditions' => array('id' => $id),
            'recursive' => -1,
        ));

        // if not found return false
        if (empty($decayingModel)) {
            return false;
        }

        //if the user is a site admin, return the template without question
        if ($user['Role']['perm_site_admin']) {
            return $decayingModel;
        }

        if ($user['Organisation']['id'] == $decayingModel['DecayingModel']['org_id'] && $user['Role']['perm_decaying']) {
            return $decayingModel;
        }
        return false;
    }

}
