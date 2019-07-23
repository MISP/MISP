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

    public function fetchAllowedModels($user) {
        $conditions = array();
        if (!$user['Role']['perm_site_admin']) {
            if ($user['Role']['perm_decaying']) {
                $conditions['org_id'] = $user['Organisation']['id'];
            } else {
                return array();
            }
        }
        $decayingModels = $this->find('all', array(
            'conditions' => $conditions,
            'recursive' => -1,
            'contain' => 'DecayingModelMapping',
        ));
        foreach ($decayingModels as $i => $decayingModel) {
            $decayingModels[$i]['DecayingModel']['attribute_types'] = Hash::extract($decayingModels[$i]['DecayingModelMapping'], '{n}.attribute_type');
            unset($decayingModels[$i]['DecayingModelMapping']);
        }

        return $decayingModels;
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

    // get effective taxonomy ratio based on taxonomies attached to the attribute
    private function _getRatioScore($model, $tags)
    {
        $ratioScore = array();
        $taxonomy_base_ratio = $model['DecayingModel']['parameters']['base_score_config'];
        if (empty($taxonomy_base_ratio)) {
            return array();
        }
        $total_score = 0.0;
        foreach ($tags as $tag) {
            $namespace_predicate = explode(':', $tag['Tag']['name'])[0];
            if (isset($taxonomy_base_ratio[$namespace_predicate])) {
                $total_score += floatval($taxonomy_base_ratio[$namespace_predicate]);
            }
        }
        foreach ($tags as $i => $tag) {
            $namespace_predicate = explode(':', $tag['Tag']['name'])[0];
            if (isset($taxonomy_base_ratio[$namespace_predicate])) {
                $ratioScore[$namespace_predicate] = floatval($taxonomy_base_ratio[$namespace_predicate]) / $total_score;
            }
        }
        return $ratioScore;
    }

    // return attribute tag with event tag matching the namespace+predicate overridden
    private function getPrioritizedTag($attribute)
    {
        $tags = array();
        $overridden_tags = array();
        $temp_mapping = array();
        foreach ($attribute['EventTag'] as $i => $tag) {
            $tags[] = $tag;
            $namespace_predicate = explode('=', $tag['Tag']['name'])[0];
            $temp_mapping[$namespace_predicate] = $i;
        }
        foreach ($attribute['AttributeTag'] as $tag) {
            $namespace_predicate = explode('=', $tag['Tag']['name'])[0];
            if (isset($temp_mapping[$namespace_predicate])) { // need to override event tag
                $overridden_tags[] = array(
                    'EventTag' => $tags[$temp_mapping[$namespace_predicate]],
                    'AttributeTag' => $tag
                );
                $tags[$temp_mapping[$namespace_predicate]] = $tag;
            } else {
                $tags[] = $tag;
            }
        }
        return array('tags' => $tags, 'overridden' => $overridden_tags);
    }

    public function computeBasescore($model, $attribute)
    {
        $temp = $this->getPrioritizedTag($attribute);
        $tags = $temp['tags'];
        $overridden_tags = $temp['overridden'];
        $taxonomy_effective_ratios = $this->_getRatioScore($model, $tags);
        $base_score = isset($model['DecayingModel']['parameters']['default_base_score']) ? $model['DecayingModel']['parameters']['default_base_score'] : 0 ;
        if (!empty($taxonomy_effective_ratios)) {
            foreach ($tags as $k => $tag) {
                $taxonomy = explode(':', $tag['Tag']['name'])[0];
                if (isset($taxonomy_effective_ratios[$taxonomy])) {
                    $base_score += $taxonomy_effective_ratios[$taxonomy] * $tag['Tag']['numerical_value'];
                }
            }
        }
        return array('base_score' => $base_score, 'overridden' => $overridden_tags, 'tags' => $tags, 'taxonomy_effective_ratios' => $taxonomy_effective_ratios);
    }

    // compute the current score for the provided atribute with the provided model
    public function computeScore($model, $elapsed_time, $base_score)
    {
        if ($elapsed_time < 0) {
            return 0;
        }
        $delta = $model['DecayingModel']['parameters']['delta'];
        $tau = $model['DecayingModel']['parameters']['tau']*24*60*60;
        $score = $base_score * (1 - pow($elapsed_time / $tau, 1 / $delta));
        return $score < 0 ? 0 : $score;
    }

    public function computeCurrentScore($model, $attribute, $base_score = false, $last_sighting_timestamp = false)
    {
        if ($base_score === false) {
            $base_score = $this->computeBasescore($model, $attribute)['base_score'];
        }
        if ($last_sighting_timestamp === false) {
            $last_sighting_timestamp = $this->Sighting->listSightings($user, $attribute_id, 'attribute', false, 0, true)[0]['Sighting']['date_sighting'];
        }
        $timestamp = time();
        return $this->computeScore($model, $timestamp - $last_sighting_timestamp, $base_score);
    }

    // compute the score at the given timestamp for the provided atribute with the provided model
    public function computeScoreForTimestamp($model, $attribute, $timestamp, $last_sighting_timestamp, $base_score)
    {
        $t = $timestamp - $last_sighting_timestamp;
        if ($t < 0) {
            return 0;
        }
        $delta = $model['DecayingModel']['parameters']['delta'];
        $tau = $model['DecayingModel']['parameters']['tau']*24*60*60;
        $score = $base_score * (1 - pow($t / $tau, 1 / $delta));
        return $score < 0 ? 0 : $score;
    }

    // returns timestamp set to the rounded hour
    public function round_timestamp_to_hour($time)
    {
        $offset = $time % 3600;
        return $time - $offset;
    }

    public function getScoreOvertime($user, $model_id, $attribute_id)
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
                $attribute['EventTag'][] = $tag['EventTag'];
            }
        }
        $model = $this->checkAuthorisation($user, $model_id, true);
        if ($model === false) {
            throw new NotFoundException(__('Model not found'));
        }
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
        $base_score_config = $this->computeBasescore($model, $attribute);
        $base_score = $base_score_config['base_score'];

        // generate time span from oldest timestamp to last decay, resolution is hours
        $score_overtime = array();
        $rounded_sightings = array();
        $sighting_index = 0;
        for ($t=$start_time; $t < $end_time; $t+=3600) {
            // fetch closest sighting to the current time
            $sighting_index = $this->get_closest_sighting($sightings, $t, $sighting_index);
            $last_sighting = $this->round_timestamp_to_hour($sightings[$sighting_index]['Sighting']['date_sighting']);
            $sightings[$sighting_index]['Sighting']['rounded_timestamp'] = $last_sighting;
            $elapsed_time = $t - $last_sighting;
            $score_overtime[$t] = $this->computeScore($model, $elapsed_time, $base_score);
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
            'current_score' => $this->computeCurrentScore($model, $attribute, $base_score, $sightings[count($sightings)-1]['Sighting']['date_sighting'])
        );
    }

    public function get_closest_sighting($sightings, $time, $previous_index)
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

}
