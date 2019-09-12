<?php
include_once 'Base.php';

class Polynomial extends DecayingModelBase
{
    function __construct() {
        $this->description = __('The implementation of the decaying formula from the paper `An indicator scoring method for MISP platforms`.');
    }

    public function computeScore($model, $attribute, $base_score, $elapsed_time)
    {
        if ($elapsed_time < 0) {
            return 0;
        }
        $decay_speed = $model['DecayingModel']['parameters']['decay_speed'];
        $lifetime = $model['DecayingModel']['parameters']['lifetime']*24*60*60;
        $score = $base_score * (1 - pow($elapsed_time / $lifetime, 1 / $decay_speed));
        return $score < 0 ? 0 : $score;
    }

    public function isDecayed($model, $attribute, $score)
    {
        $threshold = $model['DecayingModel']['parameters']['threshold'];
        return $threshold > $score;
    }
}
?>
