<?php
abstract class DecayingModelBase
{
    public function checkLoading()
    {
        return 'BONFIRE LIT';
    }

    // get effective taxonomy ratio based on taxonomies attached to the attribute
    protected function __getRatioScore($model, $tags)
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
    protected function __getPrioritizedTag($attribute)
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
        $temp = $this->__getPrioritizedTag($attribute);
        $tags = $temp['tags'];
        $overridden_tags = $temp['overridden'];
        $taxonomy_effective_ratios = $this->__getRatioScore($model, $tags);
        $default_base_score = isset($model['DecayingModel']['parameters']['default_base_score']) ? $model['DecayingModel']['parameters']['default_base_score'] : 0 ;
        $base_score = $default_base_score;
        if (!empty($taxonomy_effective_ratios)) {
            foreach ($tags as $k => $tag) {
                $taxonomy = explode(':', $tag['Tag']['name'])[0];
                if (isset($taxonomy_effective_ratios[$taxonomy])) {
                    $base_score += $taxonomy_effective_ratios[$taxonomy] * $tag['Tag']['numerical_value'];
                }
            }
        }
        return array('base_score' => $base_score, 'overridden' => $overridden_tags, 'tags' => $tags, 'taxonomy_effective_ratios' => $taxonomy_effective_ratios, 'default_base_score' => $default_base_score);
    }

    // compute the current score for the provided attribute according to the last sighting with the provided model
    final public function computeCurrentScore($model, $attribute, $base_score = false, $last_sighting_timestamp = false)
    {
        if ($base_score === false) {
            $base_score = $this->computeBasescore($model, $attribute)['base_score'];
        }
        if ($last_sighting_timestamp === false) {
            $this->Sighting = ClassRegistry::init('Sighting');
            $last_sighting_timestamp = $this->Sighting->listSightings($user, $attribute_id, 'attribute', false, 0, true)[0]['Sighting']['date_sighting'];
        }
        $timestamp = time();
        return $this->computeScore($model, $attribute, $base_score, $timestamp - $last_sighting_timestamp);
    }

    // compute the score for the provided attribute according to the elapsed time with the provided model
    abstract public function computeScore($model, $attribute, $base_score, $elapsed_time);
}

?>
