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

    private $modelCache = [];
    private $modelCacheForType = [];

    private $__registered_model_classes = array(); // Proxy for already instantiated classes
    public $allowed_overrides = array('threshold' => 1, 'lifetime' => 1, 'decay_speed' => 1);

    /** @var array */
    private $defaultModelsCache;

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

        if (!isset($this->data['DecayingModel']['name'])) { // Model must have a name
            return false;
        }
        if (!isset($this->data['DecayingModel']['all_orgs'])) { // visible to all orgs by default
            $this->data['DecayingModel']['all_orgs'] = 1;
        }

        if (!isset($this->data['DecayingModel']['formula'])) { // default to polynomial
            $this->data['DecayingModel']['formula'] = 'polynomial';
        }

        if ($this->data['DecayingModel']['formula'] == 'polynomial') {
            if (isset($this->data['DecayingModel']['parameters']['settings'])) { // polynomial doesn't have custom settings
                $this->data['DecayingModel']['parameters']['settings'] = '{}';
            }
        } else if (
            isset($this->data['DecayingModel']['parameters']['settings']) &&
            $this->data['DecayingModel']['parameters']['settings'] == ''
        ) {
            $this->data['DecayingModel']['parameters']['settings'] = '{}';
        }

        if (!empty($this->data['DecayingModel']['attribute_types']) && !is_array($this->data['DecayingModel']['attribute_types'])) {
            $encoded = json_decode($this->data['DecayingModel']['attribute_types'], true);
            if ($encoded === null) {
                return false;
            }
        }

        if (!isset($this->data['DecayingModel']['parameters'])) {
            $this->data['DecayingModel']['parameters'] = array('threshold' => 0, 'lifetime' => 0, 'decay_speed' => 0);
        }
        if (
            !empty($this->data['DecayingModel']['parameters']) &&
            !is_array($this->data['DecayingModel']['parameters'])
        ) {
            $encoded = json_decode($this->data['DecayingModel']['parameters'], true);
            if ($encoded === null) {
                return false;
            }
            $encoded = $this->__adjustParameters($encoded);
            $this->data['DecayingModel']['parameters'] = json_encode($encoded);
        } else {
            $this->data['DecayingModel']['parameters'] = $this->__adjustParameters($this->data['DecayingModel']['parameters']);
        }
        return true;
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
    * May be improved at some point.
    * For now, limit the number of digits for the parameters
    */
    private function __adjustParameters($parameters)
    {
        foreach ($parameters as $name => $value) {
            if (is_array($value)) {
                $parameters[$name] = $this->__adjustParameters($parameters[$name]);
            } else if (is_numeric($value)) {
                $parameters[$name] = round($value, 4);
            } else if (!empty($value)) {
                $parameters[$name] = $value;
            } else {
                $parameters[$name] = 0;
            }
        }
        return $parameters;
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

    public function update($force=false, $user)
    {
        $new_models = $this->__load_models($force);
        if (empty($new_models)) {
            throw new NotFoundException(__('Models could not be loaded or default decaying models folder is empty'));
        }
        $temp = $this->find('all', array(
            'recursive' => -1
        ));
        $existing_models = array();
        foreach ($temp as $k => $model) { // create UUID proxy
            $existing_models[$model['DecayingModel']['uuid']] = $model['DecayingModel'];
        }
        foreach ($new_models as $k => $new_model) {
            if (isset($existing_models[$new_model['uuid']])) {
                $existing_model = $existing_models[$new_model['uuid']];
                if ($force || $new_model['version'] > $existing_model['version']) {
                    $new_model['id'] = $existing_model['id'];
                    $this->save($new_model);
                }
            } else {
                $this->create();
                $new_model['default'] = true;
                $this->save($new_model);
            }
        }
    }

    public function isEditableByCurrentUser($user, $decaying_model)
    {
        return (
            $user['Role']['perm_site_admin'] ||
            (
                $user['Role']['perm_decaying'] &&
                !$decaying_model['DecayingModel']['default'] &&
                $decaying_model['DecayingModel']['org_id'] == $user['org_id']
            )
        );
    }

    public function attachIsEditableByCurrentUser($user, $decaying_model)
    {
        $decaying_model['DecayingModel']['isEditable'] = $this->isEditableByCurrentUser($user, $decaying_model);
        return $decaying_model;
    }

    public function fetchAllDefaultModel($user)
    {
        $default_models = $this->fetchAllAllowedModels($user, false, array(), array('DecayingModel.default' => true));
        return $default_models;
    }

    public function fetchAllAllowedModels($user, $full=true, $filters=array(), $additionalConditions=array())
    {
        $conditions = array();
        if (!$user['Role']['perm_site_admin']) {
            $conditions['OR'] = array(
                'org_id' => $user['Organisation']['id'],
                'all_orgs' => 1
            );
        }
        if (!empty($filters)) {
            if (isset($filters['my_models']) && $filters['my_models']) {
                $conditions[] = array('DecayingModel.org_id' => $user['Organisation']['id']);
            } elseif (isset($filters['default_models']) && $filters['default_models']) {
                $conditions[] = array('not' => array('DecayingModel.uuid' => null));
            }
        }
        $conditions[] = array('AND' => $additionalConditions);
        $decayingModels = $this->find('all', array(
            'conditions' => $conditions,
            'include' => $full ? 'DecayingModelMapping' : ''
        ));
        foreach ($decayingModels as $i => $decayingModel) { // includes both model default mapping and user mappings
            if ($full) {
                $decayingModels[$i]['DecayingModel']['attribute_types'] = $decayingModels[$i]['DecayingModel']['attribute_types'] + Hash::extract($decayingModels[$i]['DecayingModelMapping'], '{n}.attribute_type');
                unset($decayingModels[$i]['DecayingModelMapping']);
                $decayingModels[$i]['DecayingModel']['attribute_types'] = array_unique($decayingModels[$i]['DecayingModel']['attribute_types']);
            }
            $decayingModels[$i]['DecayingModel']['isEditable'] = $this->isEditableByCurrentUser($user, $decayingModels[$i]);
        }

        return $decayingModels;
    }

    public function fetchModels($user, $ids, $full=true, $conditions=array(), $attach_editable=0)
    {
        if (is_numeric($ids)) {
            $ids = array($ids);
        }
        $models = array();
        foreach ($ids as $id) {
            $model = $this->fetchModel($user, $id, $full, $conditions, $attach_editable);
            if (!empty($model)) {
                $models[] = $model;
            }
        }
        return $models;
    }

    // Method that fetches decayingModel
    // very flexible, it's basically a replacement for find, with the addition that it restricts access based on user
    // - full attach Attribute types associated to the requested model
    public function fetchModel($user, $id, $full=true, $conditions=array(), $attach_editable=0)
    {
        $cacheKey = sprintf('%s', $id);
        if (isset($this->modelCache[$cacheKey])) {
            return $this->modelCache[$cacheKey];
        }
        $conditions['id'] = $id;
        $searchOptions = array(
            'conditions' => $conditions,
        );
        if (!$full) {
            $searchOptions['recursive'] = -1;
        }
        $decayingModel = $this->find('first', $searchOptions);

        // if not found throw
        if (empty($decayingModel)) {
            return array();
        }
        if (
            !$user['Role']['perm_site_admin'] &&
            !(  // check owner and visibility
                $user['Organisation']['id'] == $decayingModel['DecayingModel']['org_id'] ||
                $decayingModel['DecayingModel']['all_orgs']
            )
        ) {
            return array();
        }

        if ($full) {
            $decayingModel['DecayingModel']['attribute_types'] = $this->DecayingModelMapping->getAssociatedTypes($user, $decayingModel);
        }
        $decayingModel = $this->attachIsEditableByCurrentUser($user, $decayingModel);
        $this->modelCache[$cacheKey] = $decayingModel;
        return $decayingModel;
    }

    // filter out taxonomies and entries not having a numerical value
    // create_non_existing_tags will create (on-the-fly/non-presistent) tags that are present in the taxonomy but not created yet
    public function listTaxonomiesWithNumericalValue($create_non_existing_tags=1)
    {
        $this->Taxonomy = ClassRegistry::init('Taxonomy');
        $this->Tag = ClassRegistry::init('Tag');
        $taxonomies = $this->Taxonomy->listTaxonomies(array('full' => true, 'enabled' => true));
        $excluded_taxonomies = array();
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
                                $upperTagName = strtoupper($tag_name);
                                if (isset($tags[$upperTagName])) {
                                    $taxonomies[$namespace]['TaxonomyPredicate'][$p]['TaxonomyEntry'][$e]['Tag'] = $tags[$upperTagName]['Tag'];
                                } else { // tag is not created yet. Create a false one.
                                    $taxonomies[$namespace]['TaxonomyPredicate'][$p]['TaxonomyEntry'][$e]['Tag'] = array(
                                        'id' => 0,
                                        'name' => $tag_name,
                                        'colour' => 'grey',
                                    );
                                }
                                // Take care of numerical_value override
                                if (isset($tags[$upperTagName]['Tag']['original_numerical_value']) && is_numeric($tags[$upperTagName]['Tag']['original_numerical_value'])) {
                                    $taxonomies[$namespace]['TaxonomyPredicate'][$p]['TaxonomyEntry'][$e]['original_numerical_value'] = $tags[$upperTagName]['Tag']['original_numerical_value'];
                                    $taxonomies[$namespace]['TaxonomyPredicate'][$p]['TaxonomyEntry'][$e]['numerical_value'] = $tags[$upperTagName]['Tag']['numerical_value'];
                                }
                                // In some cases, tags may not have a numerical_value. Make sure it has one.
                                if (empty($taxonomies[$namespace]['TaxonomyPredicate'][$p]['TaxonomyEntry'][$e]['Tag']['numerical_value']) && !empty($entry['numerical_value'])) {
                                    $taxonomies[$namespace]['TaxonomyPredicate'][$p]['TaxonomyEntry'][$e]['Tag']['numerical_value'] = $entry['numerical_value'];
                                }
                            }
                        }
                        if (empty($taxonomies[$namespace]['TaxonomyPredicate'][$p]['TaxonomyEntry'])) {
                            unset($taxonomies[$namespace]['TaxonomyPredicate'][$p]);
                        } else {
                            $taxonomies[$namespace]['TaxonomyPredicate'][$p]['TaxonomyEntry'] = array_values($taxonomies[$namespace]['TaxonomyPredicate'][$p]['TaxonomyEntry']);
                        }
                    } else { // accept predicates that have a numerical value
                        if (!is_numeric($predicate['numerical_value'])) {
                            unset($taxonomies[$namespace]['TaxonomyPredicate'][$p]);
                        } else {
                            $tag_name = sprintf('%s:%s', $taxonomy['namespace'], $predicate['value']);
                            if (isset($tags[$upperTagName])) {
                                $taxonomies[$namespace]['TaxonomyPredicate'][$p]['Tag'] = $tags[$upperTagName]['Tag'];
                            } else { // tag is not created yet. Create a false one.
                                $taxonomies[$namespace]['TaxonomyPredicate'][$p]['Tag'] = array(
                                    'id' => 0,
                                    'name' => $tag_name,
                                    'colour' => 'grey',
                                );
                            }
                            $taxonomies[$namespace]['TaxonomyPredicate'][$p]['numerical_predicate'] = true;
                            $taxonomies[$namespace]['TaxonomyPredicate'][$p]['Tag']['numerical_value'] = $predicate['numerical_value'];
                            // Take care of numerical_value override
                            if (isset($tags[$upperTagName]['Tag']['original_numerical_value']) && is_numeric($tags[$upperTagName]['Tag']['original_numerical_value'])) {
                                $taxonomies[$namespace]['TaxonomyPredicate'][$p]['original_numerical_value'] = $tags[$upperTagName]['Tag']['original_numerical_value'];
                                $taxonomies[$namespace]['TaxonomyPredicate'][$p]['numerical_value'] = $tags[$upperTagName]['Tag']['numerical_value'];
                            }
                            // In some cases, tags may not have a numerical_value. Make sure it has one.
                            if (empty($taxonomies[$namespace]['TaxonomyPredicate'][$p]['Tag']['numerical_value']) && !empty($predicate['numerical_value'])) {
                                $taxonomies[$namespace]['TaxonomyPredicate'][$p]['Tag']['numerical_value'] = $predicate['numerical_value'];
                            }
                        }
                    }
                    
                }
                if (empty($taxonomies[$namespace]['TaxonomyPredicate'])) {
                    $excluded_taxonomies[$namespace] = array('taxonomy' => $taxonomies[$namespace], 'reason' => __('No tags nor predicates with `numerical_value`'));
                    unset($taxonomies[$namespace]);
                } else {
                    $taxonomies[$namespace]['TaxonomyPredicate'] = array_values($taxonomies[$namespace]['TaxonomyPredicate']);
                }
            } else {
                unset($taxonomies[$namespace]);
                $excluded_taxonomies[$namespace] = array('taxonomy' => $taxonomies[$namespace], 'reason' => __('No predicate'));
            }
        }
        return array(
            'taxonomies' => $taxonomies,
            'excluded_taxonomies' => $excluded_taxonomies,
            'not_having_numerical_value' => $start_count - count($taxonomies)
        );
    }

    // Include a PHP file and return an instanciation of the formula class
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
                try {
                    $model_class = ClassRegistry::init($expected_classname);
                    if ($model_class->checkLoading() === 'BONFIRE LIT') {
                        return $model_class;
                    }
                } catch (Exception $e) {
                    $this->Log = ClassRegistry::init('Log');
                    $this->Log->create();
                    $this->Log->saveOrFailSilently(array(
                        'org' => 'SYSTEM',
                        'model' => 'DecayingModel',
                        'model_id' => 0,
                        'email' => 'SYSTEM',
                        'action' => 'include_formula',
                        'title' => sprintf('Error while trying to include file `%s`: %s', $filename, $e->getMessage()),
                        'change' => ''
                    ));
                    return false;
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
            $available_formulas[get_class($model_class)] = array(
                'parent_class' => get_parent_class($model_class) == 'Polynomial' || get_class($model_class) == 'Polynomial' ? 'Polynomial' : get_class($model_class),
                'description' => $model_class->description
            );
        }
        return $available_formulas;
    }

    // Get a instance of the class associated to a model
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
    public function round_timestamp_to_hour($time, $floor=1)
    {
        if ($floor) {
            return floor((float) $time / 3600) * 3600;
        } else {
            return round((float) $time / 3600) * 3600;
        }
    }

    // Returns score overtime, sightings, base_score computation and other useful information
    public function getScoreOvertime($user, $model_id, $attribute_id, $model_overrides)
    {
        $this->Attribute = ClassRegistry::init('MispAttribute');
        $attribute = $this->Attribute->fetchAttributes($user, array(
            'conditions' => array('Attribute.id' => $attribute_id),
            'contain' => array('AttributeTag' => array('Tag')),
            'flatten' => 1
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
        if (empty($model)) {
            throw new NotFoundException(__('No Decaying Model with the provided ID exists'));
        }
        if (!empty($model_overrides)) {
            $model = $this->overrideModelParameters($model, $model_overrides);
        }
        $this->Computation = $this->getModelClass($model);
        $this->Sighting = ClassRegistry::init('Sighting');
        $sightings = $this->Sighting->listSightings($user, $attribute_id, 'attribute', false, 0, false);
        if (empty($sightings)) {
            if (!is_null($attribute['Attribute']['last_seen'])) {
                $falseSighting = (new DateTime($attribute['Attribute']['last_seen']))->format('U');
            } else {
                $falseSighting = $attribute['Attribute']['timestamp'];
            }
            $sightings = array(array('Sighting' => array('date_sighting' => $falseSighting))); // simulate a Sighting nonetheless
        }
        foreach ($sightings as $i => $sighting) {
            $sightings[$i]['Sighting']['rounded_timestamp'] = $this->round_timestamp_to_hour($sighting['Sighting']['date_sighting']);
        }
        // get start time
        $start_time = $attribute['Attribute']['timestamp'];
        if (!is_null($attribute['Attribute']['last_seen'])) {
            $start_time = (new DateTime($attribute['Attribute']['last_seen']))->format('U');
        }
        $start_time = $sightings[0]['Sighting']['date_sighting'] < $start_time ? $sightings[0]['Sighting']['date_sighting'] : $start_time;
        $start_time = intval($start_time);
        $start_time = $this->round_timestamp_to_hour($start_time);
        // get end time
        $last_sighting_timestamp = $sightings[count($sightings)-1]['Sighting']['date_sighting'];
        if ($attribute['Attribute']['timestamp'] > $last_sighting_timestamp) { // The attribute was modified after the last sighting, simulate a Sighting
            if (!is_null($attribute['Attribute']['timestamp'])) {
                $falseSighting = (new DateTime($attribute['Attribute']['last_seen']))->format('U');
            } else {
                $falseSighting = $attribute['timestamp'];
            }
            $sightings[count($sightings)] = array(
                'Sighting' => array(
                    'date_sighting' => $falseSighting,
                    'type' => 0, 
                    'rounded_timestamp' => $this->round_timestamp_to_hour($falseSighting)
                )
            );
            if (!is_null($attribute['Attribute']['timestamp'])) {
                $last_sighting_timestamp = (new DateTime($attribute['Attribute']['last_seen']))->format('U');
            } else {
                $last_sighting_timestamp = $attribute['Attribute']['timestamp'];
            }
        }
        $end_time = $last_sighting_timestamp + $model['DecayingModel']['parameters']['lifetime']*24*60*60;
        $end_time = $this->round_timestamp_to_hour($end_time);
        $base_score_config = $this->Computation->computeBasescore($model, $attribute['Attribute']);
        $base_score = $base_score_config['base_score'];

        // generate time range from oldest timestamp to last decay, resolution is hours
        $score_overtime = array();
        $rounded_sightings = array();
        $sighting_index = 0;
        if ($this->Computation::REQUIRES_SIGHTINGS) {
            $all_sighting_index = 0;
            $all_sightings = $this->Sighting->listSightings($user, $attribute_id, 'attribute', false, false, false);
        }
        for ($t=$start_time; $t < $end_time; $t+=3600) {
            // fetch closest sighting to the current time
            $sighting_index = $this->getClosestSighting($sightings, $t, $sighting_index);
            $last_sighting = $sightings[$sighting_index]['Sighting']['rounded_timestamp'];
            $elapsed_time = $t - $last_sighting;
            if ($this->Computation::REQUIRES_SIGHTINGS) {
                $all_sighting_index = $this->getClosestSighting($all_sightings, $t, $all_sighting_index);
                $attribute['Attribute']['Sighting'] = array_slice($all_sightings, 0, $all_sighting_index);
            }
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
            'current_score' => $this->Computation->computeCurrentScore($user, $model, $attribute['Attribute'], $base_score, $last_sighting_timestamp)['score'],
            'Model' => $model['DecayingModel']
        );
    }

    // Get closest the Sighting for a given time
    public function getClosestSighting($sightings, $time, $offset)
    {
        if (count($sightings) <= $offset+1) {
            return $offset;
        }
        $max_time = $time + 3600;
        $next_index = $offset+1;
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

    public function overrideModelParameters($model, $model_overrides)
    {
        foreach ($model_overrides as $parameter => $value) {
            if (isset($this->allowed_overrides[$parameter])) {
                $model['DecayingModel']['parameters'][$parameter] = $value;
            }
        }
        return $model;
    }

    public function attachScoresToAttribute($user, $attribute, $model_id=false, $model_overrides=array(), $include_full_model=0)
    {
        $models = array();
        if ($model_id === false) { // fetch all allowed and associated models
            $associated_model_ids = $this->DecayingModelMapping->getAssociatedModels($user, $attribute['type'], true);
            $associated_model_ids = isset($associated_model_ids[$attribute['type']]) ? array_values($associated_model_ids[$attribute['type']]) : array();
            if (isset($this->modelCacheForType[$attribute['type']])) {
                $models = $this->modelCacheForType[$attribute['type']];
            } else if (!empty($associated_model_ids)) {
                $models = $this->fetchModels($user, $associated_model_ids, false, array('enabled' => true));
                $this->modelCacheForType[$attribute['type']] = $models;
            }
        } else {
            $models = $this->fetchModels($user, $model_id, false, array());
            $this->modelCacheForType[$attribute['type']] = $models;
        }
        foreach ($models as $model) {
            if (!empty($model_overrides)) {
                $model = $this->overrideModelParameters($model, $model_overrides);
            }
            $score = $this->getScore($attribute, $model, $user);
            $decayed = $this->isDecayed($attribute, $model, $score['score']);
            $to_attach = array(
                'score' => $score['score'],
                'base_score' => $score['base_score'],
                'decayed' => $decayed,
                'DecayingModel' => array(
                    'id' => $model['DecayingModel']['id'],
                    'name' => $model['DecayingModel']['name']
                )
            );
            if ($include_full_model) {
                $to_attach['DecayingModel'] = $model['DecayingModel'];
            }
            $attribute['decay_score'][] = $to_attach;
        }
        return $attribute;
    }

    /**
     * @param array $user
     * @param array $event
     * @param int|bool $modelId
     * @param array $modelOverrides
     * @param bool $includeFullModel
     * @return array
     */
    public function attachScoresToEvent(array $user, array $event, $modelId = false, $modelOverrides = [], $includeFullModel = false)
    {
        if ($modelId === false) { // fetch all allowed and associated models
            if (isset($this->defaultModelsCache[$user['id']])) {
                $models = $this->defaultModelsCache[$user['id']];
            } else {
                $models = $this->fetchAllAllowedModels($user, false, [], ['DecayingModel.enabled' => true]);
                $this->defaultModelsCache[$user['id']] = $models;
            }
        } else {
            $models = $this->fetchModels($user, $modelId, false, array());
        }
        foreach ($models as $model) {
            if (!empty($modelOverrides)) {
                $model = $this->overrideModelParameters($model, $modelOverrides);
            }
            $eventScore = $this->getScoreForEvent($user, $event, $model);
            $decayed = $this->isEventDecayed($model, $eventScore['score']);
            $to_attach = [
                'score' => $eventScore['score'],
                'base_score' => $eventScore['base_score'],
                'decayed' => $decayed,
                'DecayingModel' => [
                    'id' => $model['DecayingModel']['id'],
                    'name' => $model['DecayingModel']['name']
                ]
            ];
            if ($includeFullModel) {
                $to_attach['DecayingModel'] = $model['DecayingModel'];
            }
            $event['event_scores'][] = $to_attach;
        }
        return $event;
    }

    public function getScore($attribute, $model, $user=false)
    {
        if (is_numeric($attribute) && $user !== false) {
            $this->Attribute = ClassRegistry::init('MispAttribute');
            $attribute = $this->Attribute->fetchAttributes($user, array(
                'conditions' => array('Attribute.id' => $attribute),
                'contain' => array('AttributeTag' => array('Tag'))
            ));
        }
        if (is_numeric($model) && $user !== false) {
            $model = $this->fetchModel($user, $model);
            if (empty($model)) {
                throw new NotFoundException(__('No Decaying Model with the provided ID exists'));
            }
        }
        $this->Computation = $this->getModelClass($model);
        return $this->Computation->computeCurrentScore($user, $model, $attribute);
    }

    public function getScoreForEvent($user, $event, $model): array
    {
        $this->Computation = $this->getModelClass($model);
        return $this->Computation->computeEventScore($user, $model, $event);
    }

    public function isEventDecayed(array $model, float $score): bool
    {
        $threshold = $model['DecayingModel']['parameters']['threshold'];
        return $threshold > $score;
    }

    public function isDecayed($attribute, $model, $score=false, $user=false)
    {
        if ($score === false) {
            $score = $this->getScore($attribute, $model, $user)['score'];
        }
        $this->Computation = $this->getModelClass($model);
        return $this->Computation->isDecayed($model, $attribute, $score);
    }

}
