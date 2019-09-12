<?php
abstract class DecayingModelBase
{
    public function checkLoading()
    {
        return 'BONFIRE LIT';
    }

    // Get effective taxonomy ratio based on taxonomies attached to the attribute
    // Basically, it adapts the ratio defined in the model to fit the actual attached tags 
    protected function __getRatioScore($model, $tags)
    {
        $ratioScore = array();
        $taxonomy_base_ratio = $model['DecayingModel']['parameters']['base_score_config'];
        if (empty($taxonomy_base_ratio)) {
            return array();
        }
        $total_score = 0.0;
        foreach ($tags as $tag) {
            $namespace_predicate = explode('=', $tag['Tag']['name'])[0];
            if (isset($taxonomy_base_ratio[$namespace_predicate]) && is_numeric($tag['Tag']['numerical_value'])) {
                $total_score += floatval($taxonomy_base_ratio[$namespace_predicate]);
            }
        }
        foreach ($tags as $i => $tag) {
            $namespace_predicate = explode('=', $tag['Tag']['name'])[0];
            if (isset($taxonomy_base_ratio[$namespace_predicate]) && is_numeric($tag['Tag']['numerical_value'])) {
                $ratioScore[$namespace_predicate] = floatval($taxonomy_base_ratio[$namespace_predicate]) / $total_score;
            }
        }
        return $ratioScore;
    }

    // return attribute tag with event tag matching the namespace+predicate overridden
    protected function __getPrioritisedTag($attribute)
    {
        $tags = array();
        $overridden_tags = array();
        $temp_mapping = array();
        if (isset($attribute['EventTag'])) {
            foreach ($attribute['EventTag'] as $i => $tag) {
                $tags[] = $tag;
                $namespace_predicate = explode('=', $tag['Tag']['name'])[0];
                $temp_mapping[$namespace_predicate][] = $i;
            }
        }
        if (isset($attribute['AttributeTag'])) {
            foreach ($attribute['AttributeTag'] as $tag) {
                $namespace_predicate = explode('=', $tag['Tag']['name'])[0];
                if (!empty($temp_mapping[$namespace_predicate])) { // need to override event tag
                    foreach ($temp_mapping[$namespace_predicate] as $i => $eventtag_index) {
                        $overridden_tags[] = array(
                            'EventTag' => $tags[$eventtag_index],
                            'AttributeTag' => $tag
                        );
                        if ($i === 0)  { // override first one
                            $tags[$eventtag_index] = $tag;
                        } else { // remove remaining overriden
                            unset($tags[$eventtag_index]);
                        }
                    }
                } else {
                    $tags[] = $tag;
                }
            }
        }
        return array('tags' => array_values($tags), 'overridden' => $overridden_tags);
    }

    public function computeBasescore($model, $attribute)
    {
        $temp = $this->__getPrioritisedTag($attribute);
        $tags = $temp['tags'];
        $overridden_tags = $temp['overridden'];
        $taxonomy_effective_ratios = $this->__getRatioScore($model, $tags);
        $default_base_score = isset($model['DecayingModel']['parameters']['default_base_score']) ? $model['DecayingModel']['parameters']['default_base_score'] : 0 ;
        $base_score = 0;
        $flag_contain_matching_taxonomy = false;
        if (!empty($taxonomy_effective_ratios)) {
            foreach ($tags as $k => $tag) {
                $taxonomy = explode('=', $tag['Tag']['name'])[0];
                if (isset($taxonomy_effective_ratios[$taxonomy])) {
                    $flag_contain_matching_taxonomy = true;
                    $base_score += $taxonomy_effective_ratios[$taxonomy] * $tag['Tag']['numerical_value'];
                }
            }
        }
        if (!$flag_contain_matching_taxonomy) {
            $base_score = $default_base_score;
        }
        return array(
            'base_score' => $base_score,
            'overridden' => $overridden_tags,
            'tags' => $tags,
            'taxonomy_effective_ratios' => $taxonomy_effective_ratios,
            'default_base_score' => $default_base_score
        );
    }

    // Compute the current score for the provided attribute according to the last sighting with the provided model
    final public function computeCurrentScore($user, $model, $attribute, $base_score = false, $last_sighting_timestamp = false)
    {
        if ($base_score === false) {
            $base_score = $this->computeBasescore($model, $attribute)['base_score'];
        }
        if ($last_sighting_timestamp === false) {
            $this->Sighting = ClassRegistry::init('Sighting');
            $all_sightings = $this->Sighting->listSightings($user, $attribute['id'], 'attribute', false, 0, true);
            if (!empty($all_sightings)) {
                $last_sighting_timestamp = $all_sightings[0]['Sighting']['date_sighting'];
            } else {
                $last_sighting_timestamp = $attribute['timestamp']; // if no sighting, take the last update time
            }
        }
        if ($attribute['timestamp'] > $last_sighting_timestamp) { // The attribute was modified after the last sighting
            $last_sighting_timestamp = $attribute['timestamp'];
        }
        $timestamp = time();
        return $this->computeScore($model, $attribute, $base_score, $timestamp - $last_sighting_timestamp);
    }

    // Compute the score for the provided attribute according to the elapsed time with the provided model
    abstract public function computeScore($model, $attribute, $base_score, $elapsed_time);
    // Return a True if the attribute should be marked as decayed
    abstract public function isDecayed($model, $attribute, $score);
}

?>
