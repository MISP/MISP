<?php
include_once 'Base.php';

class Sightings extends DecayingModelBase
{
    const REQUIRES_SIGHTINGS = true;

    function __construct() {
        $this->description = __('A Decaying model based on reported true positives and false positives.');
    }

    public function computeScore($model, $attribute, $base_score, $elapsed_time)
    {
        $settings = $model['DecayingModel']['parameters']['settings'];
        $minimum_sightings = isset($settings['minimum_sightings']) ? $settings['minimum_sightings'] : 1;
        $true_positive_offset = isset($settings['true_positive_offset']) ? $settings['true_positive_offset'] : 0;
        $false_positive_offset = isset($settings['false_positive_offset']) ? $settings['false_positive_offset'] : 0;

        $sightings = $attribute['Sighting'];
        $true_positives = array_filter($sightings, function ($item) {
                return $item['Sighting']['type'] == '0';
        });

        $total_count = count($sightings);
        $true_positive_count = count($true_positives);

        // $minimum_sightings should be checked before adding the offsets, otherwise
        // the offsets will count as sightings.
        if ($total_count < $minimum_sightings) {
                return $base_score;
        }

        $total_count = $total_count + $true_positive_offset + $false_positive_offset;
        $true_positive_count = $true_positive_count + $true_positive_offset;

        return $true_positive_count / $total_count * $base_score;
    }

    public function isDecayed($model, $attribute, $score)
    {
        $threshold = $model['DecayingModel']['parameters']['threshold'];
        return $threshold > $score;
    }
}
