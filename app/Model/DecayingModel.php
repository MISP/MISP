<?php

App::uses('AppModel', 'Model');
App::uses('Folder', 'Utility');
App::uses('File', 'Utility');

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

    private $__registered_model_classes = array();

    public function afterFind($results, $primary = false) {
        foreach ($results as $k => $v) {
            $results[$k]['DecayingModel']['isDefault'] = $this->isDefaultModel($v);
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

        if (
            isset($this->data['DecayingModel']['parameters']) &&
            !empty($this->data['DecayingModel']['parameters']) &&
            !is_array($this->data['DecayingModel']['parameters'])
        ) {
            $encoded = json_decode($this->data['DecayingModel']['parameters'], true);
            if ($encoded !== null) {
                $validation = $this->__validateParameters($encoded);
                if ($validation !== false) {
                    $this->data['DecayingModel']['parameters'] = json_encode($encoded);
                    return true;
                }
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
        if (isset($this->data['DecayingModel']['parameters']['base_score_config']) && is_array($this->data['DecayingModel']['parameters']['base_score_config'])) {
            $this->data['DecayingModel']['parameters']['base_score_config'] = json_encode($this->data['DecayingModel']['parameters']['base_score_config']);
        }
        if (isset($this->data['DecayingModel']['parameters']['settings']) && is_array($this->data['DecayingModel']['parameters']['settings'])) {
            $this->data['DecayingModel']['parameters']['settings'] = json_encode($this->data['DecayingModel']['parameters']['settings']);
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

    /*
    * may be done at some point but we still want to be generic
    * so enforcing hardcoded tests here may not be the best solution
    * For now, limit the number of digits for the parameters
    */
    private function __validateParameters(&$parameters)
    {
        foreach ($parameters as $name => $value) {
            if (is_array($value)) {
                $this->__validateParameters($parameters[$name]);
            } else if (is_numeric($value)) {
                $parameters[$name] = round($value, 4);
            } else if (!empty($value)) {
                $parameters[$name] = $value;
            } else {
                $parameters[$name] = 0;
            }
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

    public function isDefaultModel($decaying_model)
    {
        return !is_null($decaying_model['DecayingModel']['uuid']);
    }

    public function fetchAllAllowedModels($user, $full=true)
    {
        $conditions = array();
        if (!$user['Role']['perm_site_admin']) {
            $conditions['OR'] = array(
                'org_id' => $user['Organisation']['id'],
                'all_orgs' => 1
            );
        }
        $decayingModels = $this->find('all', array(
            'conditions' => $conditions,
            'include' => $full ? 'DecayingModelMapping' :''
        ));
        foreach ($decayingModels as $i => $decayingModel) { // includes both model default mapping and user mappings
            if ($full) {
                $decayingModels[$i]['DecayingModel']['attribute_types'] = $decayingModels[$i]['DecayingModel']['attribute_types'] + Hash::extract($decayingModels[$i]['DecayingModelMapping'], '{n}.attribute_type');
                unset($decayingModels[$i]['DecayingModelMapping']);
            }
        }

        return $decayingModels;
    }

    public function fetchModels($user, $ids, $full=true, $conditions=array())
    {
        $models = array();
        foreach ($ids as $id) {
            try {
                $model = $this->fetchModel($user, $id, $full, $conditions);
                $models[] = $model;
            } catch (MethodNotAllowedException $e) {
                // Just don't add the model to the result
            }
        }
        return $models;
    }

    // Method that fetches decayingModel
    // very flexible, it's basically a replacement for find, with the addition that it restricts access based on user
    // - full attach Attribute types associated to the requested model
    public function fetchModel($user, $id, $full=true, $conditions=array())
    {
        $conditions['id'] = $id;
        $searchOptions = array(
            'conditions' => $conditions,
        );
        if (!$full) {
            $searchOptions['recursive'] = -1;
        }
        $decayingModel = $this->find('first', $searchOptions);

        // if not found return false
        if (empty($decayingModel)) {
            throw new MethodNotAllowedException(__('No Decaying Model with the provided ID exists, or you are not authorised to view it.'));
        }
        if (
            !$user['Role']['perm_site_admin'] &&  // if the user is a site admin, return the model without question
            !($user['Organisation']['id'] == $decayingModel['DecayingModel']['org_id'] || $decayingModel['DecayingModel']['all_orgs'])
        ) {
            throw new MethodNotAllowedException(__('No Decaying Model with the provided ID exists, or you are not authorised to view it.'));
        }

        if ($full) {
            $decayingModel['DecayingModel']['attribute_types'] = $this->DecayingModelMapping->getAssociatedTypes($user, $decayingModel['DecayingModel']['id']);
        }
        return $decayingModel;
    }

    // filter out taxonomies and entries not having a numerical value
    public function listTaxonomiesWithNumericalValue()
    {
        $this->Taxonomy = ClassRegistry::init('Taxonomy');
        $this->Tag = ClassRegistry::init('Tag');
        $taxonomies = $this->Taxonomy->listTaxonomies(array('full' => true, 'enabled' => true));
        $start_count = count($taxonomies);
        foreach ($taxonomies as $namespace => $taxonomy) {
            if(!empty($taxonomy['TaxonomyPredicate'])) {
                $tags = $this->Tag->getTagsForNamespace($taxonomy['namespace'], false);
                foreach($taxonomy['TaxonomyPredicate'] as $p => $predicate) {
                    if(!empty($predicate['TaxonomyEntry'])) {
                        foreach ($predicate['TaxonomyEntry'] as $e => $entry) {
                            if (!is_numeric($entry['numerical_value'])) {
                                unset($taxonomies[$namespace]['TaxonomyPredicate'][$p]['TaxonomyEntry'][$e]);
                            } else {
                                $tag_name = sprintf('%s:%s="%s"', $taxonomy['namespace'], $predicate['value'], $entry['value']);
                                $taxonomies[$namespace]['TaxonomyPredicate'][$p]['TaxonomyEntry'][$e]['Tag'] = $tags[strtoupper($tag_name)]['Tag'];
                                $taxonomies[$namespace]['TaxonomyPredicate'][$p]['TaxonomyEntry'][$e]['Tag']['numerical_value'] = $entry['numerical_value'];
                            }
                        }
                        if (empty($taxonomies[$namespace]['TaxonomyPredicate'][$p]['TaxonomyEntry'])) {
                            unset($taxonomies[$namespace]['TaxonomyPredicate'][$p]);
                        } else {
                            $taxonomies[$namespace]['TaxonomyPredicate'][$p]['TaxonomyEntry'] = array_values($taxonomies[$namespace]['TaxonomyPredicate'][$p]['TaxonomyEntry']);
                        }
                    } else {
                        unset($taxonomies[$namespace]['TaxonomyPredicate'][$p]);
                    }
                }
                if (empty($taxonomies[$namespace]['TaxonomyPredicate'])) {
                    unset($taxonomies[$namespace]);
                } else {
                    $taxonomies[$namespace]['TaxonomyPredicate'] = array_values($taxonomies[$namespace]['TaxonomyPredicate']);
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

    private function __include_formula_file_and_return_instance($filename='Polynomial.php')
    {
        $formula_files = $this->__listPHPFormulaFiles(); // redundant in some cases but better be safe than sorry
        $index = array_search($filename, $formula_files);
        if ($index !== false) {
            $filename_no_extension = str_replace('.php', '', $formula_files[$index]);
            $expected_classname = $filename_no_extension;
            $full_path = APP . 'Model/DecayingModelsFormulas/' . $formula_files[$index];
            if (is_file($full_path)) {
                include_once $full_path;
                $model_class = ClassRegistry::init($expected_classname);
                if ($model_class->checkLoading() === 'BONFIRE LIT') {
                    return $model_class;
                }
            }
        }
        return false;
    }

    private function __listPHPFormulaFiles()
    {
        $dir = new Folder(APP . 'Model/DecayingModelsFormulas');
        $files = $dir->find('.*\.php', true);
        $files = array_diff($files, array('..', '.', 'Base.php'));
        return $files;
    }

    public function listAvailableFormulas()
    {
        $formula_files = $this->__listPHPFormulaFiles();
        $available_formulas = array();
        foreach ($formula_files as $formula_file) {
            $model_class = $this->__include_formula_file_and_return_instance($formula_file);
            if ($model_class === false) {
                continue;
            }
            $available_formulas[get_class($model_class)] = get_parent_class($model_class) == 'Polynomial' || get_class($model_class) == 'Polynomial' ? 'Polynomial' : get_class($model_class);
        }
        return $available_formulas;
    }

    public function getModelClass($model)
    {
        $formula_name = $model['DecayingModel']['formula'] === '' ? 'polynomial' : $model['DecayingModel']['formula'];
        $expected_filename = Inflector::humanize($formula_name) . '.php';
        if (!isset($this->__registered_model_classes[$formula_name])) {
            $model_class = $this->__include_formula_file_and_return_instance($expected_filename);
            if ($model_class === false) {
                throw new NotFoundException(sprintf(__('The class for `%s` was not found or not loaded correctly'), $formula_name));
            }
            $this->__registered_model_classes[$formula_name] = $model_class;
        }
        return $this->__registered_model_classes[$formula_name];
    }

    // returns timestamp set to the rounded hour
    public function round_timestamp_to_hour($time)
    {
        $offset = $time % 3600;
        return $time - $offset;
    }

    public function getScoreOvertime($user, $model_id, $attribute_id, $model_overrides)
    {
        $this->Attribute = ClassRegistry::init('Attribute');
        $attribute = $this->Attribute->fetchAttributesSimple($user, array(
            'conditions' => array('id' => $attribute_id),
            'contain' => array('AttributeTag' => array('Tag'))
        ));
        if (empty($attribute)) {
            throw new NotFoundException(__('Attribute not found'));
        } else {
            $attribute = $attribute[0];
            $tagConditions = array('EventTag.event_id' => $attribute['Attribute']['event_id']);
            $temp = $this->Attribute->Event->EventTag->find('all', array(
                'recursive' => -1,
                'contain' => array('Tag'),
                'conditions' => $tagConditions
            ));
            foreach ($temp as $tag) {
                $tag['EventTag']['Tag'] = $tag['Tag'];
                unset($tag['Tag']);
                $attribute['Attribute']['EventTag'][] = $tag['EventTag'];
            }
            $attribute['Attribute']['AttributeTag'] = $attribute['AttributeTag'];
            unset($attribute['AttributeTag']);
        }
        $model = $this->fetchModel($user, $model_id, true);
        if ($model === false) {
            throw new NotFoundException(__('Model not found'));
        }
        if (!empty($model_overrides)) {
            $this->overrideModelParameters($model, $model_overrides);
        }
        $this->Computation = $this->getModelClass($model);
        $this->Sighting = ClassRegistry::init('Sighting');
        $sightings = $this->Sighting->listSightings($user, $attribute_id, 'attribute', false, 0, false);
        if (empty($sightings)) {
            $sightings = array(array('Sighting' => array('date_sighting' => $attribute['Attribute']['timestamp']))); // simulate a sighting nonetheless
        }
        // get start time
        $start_time = $attribute['Attribute']['timestamp'];
        // $start_time = $attribute['Attribute']['first_seen'] < $start_time ? $attribute['Attribute']['first_seen'] : $start_time;
        $start_time = $sightings[0]['Sighting']['date_sighting'] < $start_time ? $sightings[0]['Sighting']['date_sighting'] : $start_time;
        $start_time = intval($start_time);
        $start_time = $this->round_timestamp_to_hour($start_time);
        // get end time
        $end_time = $sightings[count($sightings)-1]['Sighting']['date_sighting'] + $model['DecayingModel']['parameters']['tau']*24*60*60;
        $end_time = $this->round_timestamp_to_hour($end_time);
        $base_score_config = $this->Computation->computeBasescore($model, $attribute['Attribute']);
        $base_score = $base_score_config['base_score'];

        // generate time span from oldest timestamp to last decay, resolution is hours
        $score_overtime = array();
        $rounded_sightings = array();
        $sighting_index = 0;
        for ($t=$start_time; $t < $end_time; $t+=3600) {
            // fetch closest sighting to the current time
            $sighting_index = $this->getClosestSighting($sightings, $t, $sighting_index);
            $last_sighting = $this->round_timestamp_to_hour($sightings[$sighting_index]['Sighting']['date_sighting']);
            $sightings[$sighting_index]['Sighting']['rounded_timestamp'] = $last_sighting;
            $elapsed_time = $t - $last_sighting;
            $score_overtime[$t] = $this->Computation->computeScore($model, $attribute['Attribute'], $base_score, $elapsed_time);
        }
        $csv = 'date,value' . PHP_EOL;
        foreach ($score_overtime as $t => $v) {
            $csv .= (new DateTime())->setTimestamp($t)->format('Y-m-d H:i:s') . ',' . $v . PHP_EOL;
        }
        return array(
            'csv' => $csv,
            'sightings' => $sightings,
            'base_score_config' => $base_score_config,
            'last_sighting' => $sightings[count($sightings)-1],
            'current_score' => $this->Computation->computeCurrentScore($user, $model, $attribute['Attribute'], $base_score, $sightings[count($sightings)-1]['Sighting']['date_sighting']),
            'Model' => $model['DecayingModel']
        );
    }

    public function getClosestSighting($sightings, $time, $previous_index)
    {
        if (count($sightings) <= $previous_index+1) {
            return $previous_index;
        }
        $max_time = $time + 3600;
        $next_index = $previous_index+1;
        $next_sighting = $sightings[$next_index]['Sighting']['date_sighting'];
        while ($next_sighting <= $max_time) {
            $next_index++;
            if ($next_index >= count($sightings)) {
                break;
            }
            $next_sighting = $sightings[$next_index]['Sighting']['date_sighting'];
        }
        return $next_index-1;
    }

    public function overrideModelParameters(&$model, $model_overrides)
    {
        $allowed_overrides = array('threshold' => 1);
        foreach ($model_overrides as $parameter => $value) {
            if (isset($allowed_overrides[$parameter])) {
                $model['DecayingModel']['parameters'][$parameter] = $value;
            }
        }
    }

    public function attachScoresToAttribute($user, &$attribute, $model_id=false, $model_overrides=array())
    {
        $models = array();
        if ($model_id === false) { // fetch all allowed and associated models
            $associated_model_ids = $this->DecayingModelMapping->getAssociatedModels($user, $attribute['type'], true);
            $associated_model_ids = array_values($associated_model_ids[$attribute['type']]);
            if (!empty($associated_model_ids)) {
                $models = $this->fetchModels($user, $associated_model_ids, false, array('enabled' => true));
            }
        } elseif (is_array($model_id)) {
            $models = $this->fetchModels($user, $model_id, false, array('enabled' => true));
        } else {
            $models[] = $this->fetchModel($user, $model_id, false, array('enabled' => true));
        }

        foreach ($models as $i => $model) {
            if (!empty($model_overrides)) {
                $this->overrideModelParameters($model, $model_overrides);
            }
            $score = $this->getScore($attribute, $model, $user);
            $decayed = $this->isDecayed($attribute, $model, $score);
            $attribute['decay_score'][] = array('DecayingModel' => $model['DecayingModel'], 'score' => $score, 'decayed' => $decayed);
        }
    }

    public function getScore($attribute, $model, $user=false)
    {
        if (is_numeric($attribute) && $user !== false) {
            $this->Attribute = ClassRegistry::init('Attribute');
            $attribute = $this->Attribute->fetchAttributesSimple($user, array(
                'conditions' => array('id' => $attribute),
                'contain' => array('AttributeTag' => array('Tag'))
            ));
        }
        if (is_numeric($model) && $user !== false) {
            $model = $this->fetchModel($user, $model);
        }
        $this->Computation = $this->getModelClass($model);
        return $this->Computation->computeCurrentScore($user, $model, $attribute);
    }

    public function isDecayed($attribute, $model, $score=false, $user=false)
    {
        if ($score === false) {
            $score = $this->getScore($attribute, $model, $user);
        }
        $this->Computation = $this->getModelClass($model);
        return $this->Computation->isDecayed($model, $attribute, $score);
    }

}
