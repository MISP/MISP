<?php
App::uses('AppHelper', 'View/Helper');
App::uses('DistributionLevel', 'Tools');

/**
 * View wrapper around the DistributionLevel lib so templates can pull the
 * canonical look of a distribution level with
 * $this->DistributionLevel->get($level) — or the whole table, for the ones
 * that render badges in a loop or hand it to JavaScript, with ->all().
 */
class DistributionLevelHelper extends AppHelper
{
    /**
     * @return array see DistributionLevel::all()
     */
    public function all()
    {
        return DistributionLevel::all();
    }

    /**
     * @param mixed $level
     * @return array see DistributionLevel::get()
     */
    public function get($level)
    {
        return DistributionLevel::get($level);
    }

    /**
     * @return array see DistributionLevel::fallback()
     */
    public function fallback()
    {
        return DistributionLevel::fallback();
    }
}
