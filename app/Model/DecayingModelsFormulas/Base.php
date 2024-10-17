<?php
abstract class DecayingModelBase
{
    // If REQUIRES_SIGHTINGS is true, all sightings will be added to the attribute
    // before passing the attribute to computeScore
    const REQUIRES_SIGHTINGS = false;

    public function checkLoading()
    {
        return 'BONFIRE LIT';
    }


    protected function __extractTagBasename($tagName) {
        $pieces = array();
        if (preg_match('/^[^:="]+:[^:="]+="[^:="]+"$/i', $tagName)) {
            $temp = explode(':', $tagName);
            $pieces = array_merge(array($temp[0]), explode('=', $temp[1]));
            $pieces['complete'] = $tagName;
            $pieces['namespace'] = $pieces[0];
            $pieces['predicate'] = $pieces[1];
            $pieces['2tag'] = sprintf('%s:%s', $pieces[0], $pieces[1]);
            $pieces['base'] = sprintf('%s:%s', $pieces[0], $pieces[1]);
        } elseif (preg_match('/^[^:="]+:[^:="]+$/i', $tagName)) {
            $pieces = explode(':', $tagName);
            $pieces['complete'] = $tagName;
            $pieces['namespace'] = $pieces[0];
            $pieces['predicate'] = $pieces[1];
            $pieces['2tag'] = sprintf('%s:%s', $pieces[0], $pieces[1]);
            $pieces['base'] = $pieces[0];
        } else {
            $pieces['complete'] = $tagName;
            $pieces['namespace'] = '';
            $pieces['predicate'] = '';
            $pieces['2tag'] = '';
            $pieces['base'] = $tagName;
        }
        return $pieces;
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
            $tagBaseName = $this->__extractTagBasename($tag['Tag']['name'])['base'];
            if (isset($taxonomy_base_ratio[$tagBaseName]) && is_numeric($tag['Tag']['numerical_value'])) {
                $total_score += floatval($taxonomy_base_ratio[$tagBaseName]);
            }
        }
        foreach ($tags as $i => $tag) {
            $tagBaseName = $this->__extractTagBasename($tag['Tag']['name'])['base'];
            if (isset($taxonomy_base_ratio[$tagBaseName]) && is_numeric($tag['Tag']['numerical_value'])) {
                $ratioScore[$tagBaseName] = floatval($taxonomy_base_ratio[$tagBaseName]) / $total_score;
            }
        }
        return $ratioScore;
    }

    // return attribute tag with event tag matching the tag basename overridden
    protected function __getPrioritisedTag($attribute)
    {
        $tags = array();
        $overridden_tags = array();
        $temp_mapping = array();
        if (isset($attribute['EventTag'])) {
            foreach ($attribute['EventTag'] as $i => $tag) {
                $tags[] = $tag;
                $tagBaseName = $this->__extractTagBasename($tag['Tag']['name'])['base'];
                $temp_mapping[$tagBaseName][] = $i;
            }
        }
        if (isset($attribute['AttributeTag'])) {
            foreach ($attribute['AttributeTag'] as $tag) {
                $tagBaseName = $this->__extractTagBasename($tag['Tag']['name'])['base'];
                if (!empty($temp_mapping[$tagBaseName])) { // need to override event tag
                    foreach ($temp_mapping[$tagBaseName] as $i => $eventtag_index) {
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
                $taxonomy = $this->__extractTagBasename($tag['Tag']['name'])['base'];
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
        $this->Sighting = ClassRegistry::init('Sighting');
        if ($last_sighting_timestamp === false) {
            $last_sighting = $this->Sighting->getLastSightingForAttribute($user, $attribute['id']);
            if (!empty($last_sighting)) {
                $last_sighting_timestamp = $last_sighting['Sighting']['date_sighting'];
            } elseif (!is_null($attribute['last_seen'])) {
                $last_sighting_timestamp = (new DateTime($attribute['last_seen']))->format('U');
            } else {
                $last_sighting_timestamp = $attribute['timestamp']; // if no sighting nor valid last_seen, take the last update time
            }
        }
        if ($attribute['timestamp'] > $last_sighting_timestamp) { // The attribute was modified after the last sighting
            if (!is_null($attribute['last_seen'])) {
                $last_sighting_timestamp = (new DateTime($attribute['last_seen']))->format('U');
            } else {
                $last_sighting_timestamp = $attribute['timestamp'];
            }
        }
        $timestamp = time();
        if ($this::REQUIRES_SIGHTINGS) {
            $attribute['Sighting'] = $this->Sighting->listSightings($user, $attribute['id'], 'attribute', false, false, false);
        }
        $scores = array(
            'score' => $this->computeScore($model, $attribute, $base_score, $timestamp - $last_sighting_timestamp),
            'base_score' => $base_score
        );
        return $scores;
    }

    final public function computeEventScore($user, $model, $event, $base_score = false)
    {
        $this->Sighting = ClassRegistry::init('Sighting');
        $base_score = $this->computeBasescore($model, $event)['base_score'];
        $last_timestamp = $event['Event']['publish_timestamp'];
        $timestamp = time();
        if ($this::REQUIRES_SIGHTINGS) {
            $event['Sighting'] = $this->Sighting->listSightings($user, $event['id'], 'context', false, false, false);
        }
        $scores = array(
            'score' => $this->computeScore($model, $event, $base_score, $timestamp - $last_timestamp),
            'base_score' => $base_score
        );
        return $scores;
    }

    // Compute the score for the provided attribute according to the elapsed time with the provided model
    abstract public function computeScore($model, $attribute, $base_score, $elapsed_time);
    // Return a True if the attribute should be marked as decayed
    abstract public function isDecayed($model, $attribute, $score);
}
