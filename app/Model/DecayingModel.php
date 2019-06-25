<?php

App::uses('AppModel', 'Model');

class DecayingModel extends AppModel
{
    public $actsAs = array('Containable');

    public $hasMany = array(
        'DecayingModelMapping' => array(
            'className' => 'DecayingModelMapping',
            'foreignKey' => 'model_id',
            'dependent' => true
        )
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
            if (!empty($v['DecayingModel']['attribute_types'])) {
                $decoded = json_decode($v['DecayingModel']['attribute_types'], true);
                if ($decoded === null) {
                    $decoded = array();
                }
                $results[$k]['DecayingModel']['attribute_types'] = $decoded;
            } else {
                $results[$k]['DecayingModel']['attribute_types'] = array();
            }
            if (!empty($v['DecayingModel']['ref'])) {
                $decoded = json_decode($v['DecayingModel']['ref'], true);
                if ($decoded === null) {
                    $decoded = array();
                }
                $results[$k]['DecayingModel']['ref'] = $decoded;
            }
        }
        return $results;
    }

    public function beforeValidate($options = array()) {
        parent::beforeValidate();
        if (!empty($this->data['DecayingModel']['parameters']) && !is_array($this->data['DecayingModel']['parameters'])) {
            $encoded = json_decode($this->data['DecayingModel']['parameters'], true);
            if ($encoded !== null) {
                return true;
            }
            return false;
        }
        if (!empty($this->data['DecayingModel']['attribute_types']) && !is_array($this->data['DecayingModel']['attribute_types'])) {
            $encoded = json_decode($this->data['DecayingModel']['attribute_types'], true);
            if ($encoded !== null) {
                return true;
            }
            return false;
        }
    }

    public function beforeSave($options = array()) {
        if (isset($this->data['DecayingModel']['parameters']) && is_array($this->data['DecayingModel']['parameters'])) {
            $this->data['DecayingModel']['parameters'] = json_encode($this->data['DecayingModel']['parameters']);
        }
        if (isset($this->data['DecayingModel']['attribute_types']) && is_array($this->data['DecayingModel']['attribute_types'])) {
            $this->data['DecayingModel']['attribute_types'] = json_encode($this->data['DecayingModel']['attribute_types']);
        }
        if (isset($this->data['DecayingModel']['ref']) && is_array($this->data['DecayingModel']['ref'])) {
            $this->data['DecayingModel']['ref'] = json_encode($this->data['DecayingModel']['ref']);
        }
        if (!isset($this->data['DecayingModel']['org_id'])) {
            $this->data['DecayingModel']['org_id'] = Configure::read('MISP.host_org_id');
        }

        return true;
    }

    private function __load_models($force = false)
    {
        $dir = new Folder(APP . 'files' . DS . 'misp-decaying-models' . DS . 'models');
        $files = $dir->find('.*\.json');
        $models = array();
        foreach ($files as $file) {
            $file = new File($dir->pwd() . DS . $file);
            $models[] = json_decode($file->read(), true);
            $file->close();
        }
        return $models;
    }

    public function update($force=false)
    {
        $new_models = $this->__load_models($force);
        $temp = $this->find('all', array(
            'recursive' => -1
        ));
        $existing_models = array();
        foreach ($temp as $k => $model) {
            $existing_models[$model['DecayingModel']['uuid']] = $model['DecayingModel'];
        }
        foreach ($new_models as $k => $new_model) {
            if (isset($existing_models[$new_model['uuid']])) {
                $existing_model = $existing_models[$new_model['uuid']];
                if ($force || $new_model['version'] > $existing_model['version']) {
                    $new_model['id'] = $existing_model['id'];
                    $new_model['model_id'] = $existing_model['id'];
                    $this->save($new_model);
                    $this->DecayingModelMapping->resetMappingForModel($new_model);
                }
            } else {
                $this->create();
                $this->save($new_model);
                $new_model['id'] = $this->Model->id;
                $new_model['model_id'] = $this->Model->id;
                $this->DecayingModelMapping->resetMappingForModel($new_model);
            }
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

    public function checkAuthorisation($user, $id, $full=true) {
        // fetch the bare template
        $decayingModel = $this->find('first', array(
            'conditions' => array('id' => $id),
            // 'recursive' => -1,
        ));

        // if not found return false
        if (empty($decayingModel)) {
            return false;
        }

        if ($full) {
            $decayingModel['DecayingModel']['attribute_types'] = $this->DecayingModelMapping->getAssociatedTypes($user, $decayingModel['DecayingModel']['id']);
        }

        //if the user is a site admin, return the model without question
        if ($user['Role']['perm_site_admin']) {
            return $decayingModel;
        }

        if ($user['Organisation']['id'] == $decayingModel['DecayingModel']['org_id'] && $user['Role']['perm_decaying']) {
            return $decayingModel;
        }
        return false;
    }

    // filter out taxonomies and entries not having a numerical value
    public function listTaxonomiesWithNumericalValue()
    {
        $this->Taxonomy = ClassRegistry::init('Taxonomy');
        $taxonomies = $this->Taxonomy->listTaxonomies(array('full' => true, 'enabled' => true));
        $start_count = count($taxonomies);
        foreach ($taxonomies as $namespace => $taxonomy) {
            if(!empty($taxonomy['TaxonomyPredicate'])) {
                foreach($taxonomy['TaxonomyPredicate'] as $p => $predicate) {
                    if(!empty($predicate['TaxonomyEntry'])) {
                        foreach ($predicate['TaxonomyEntry'] as $e => $entry) {
                            if (!is_numeric($entry['numerical_value'])) {
                                unset($taxonomies[$namespace]['TaxonomyPredicate'][$p]['TaxonomyEntry'][$e]);
                            }
                        }
                        if (empty($taxonomies[$namespace]['TaxonomyPredicate'][$p]['TaxonomyEntry'])) {
                            unset($taxonomies[$namespace]['TaxonomyPredicate'][$p]);
                        }
                    } else {
                        unset($taxonomies[$namespace]['TaxonomyPredicate'][$p]);
                    }
                }
                if (empty($taxonomies[$namespace]['TaxonomyPredicate'])) {
                    unset($taxonomies[$namespace]);
                }
            } else {
                unset($taxonomies[$namespace]);
            }
        }
        return array(
            'taxonomies' => $taxonomies,
            'not_having_numerical_value' => $start_count - count($taxonomies)
        );
    }

}
