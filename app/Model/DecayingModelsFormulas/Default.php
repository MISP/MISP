<?php
include_once 'Base.php';

class DecayingModelDefault extends DecayingModelBase
{
    public function computeScore($model, $attribute, $base_score, $elapsed_time)
    {
        if ($elapsed_time < 0) {
            return 0;
        }
        $delta = $model['DecayingModel']['parameters']['delta'];
        $tau = $model['DecayingModel']['parameters']['tau']*24*60*60;
        $score = $base_score * (1 - pow($elapsed_time / $tau, 1 / $delta));
        return $score < 0 ? 0 : $score;
    }
}
?>
