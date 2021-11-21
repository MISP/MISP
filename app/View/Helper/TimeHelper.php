<?php
App::uses('AppHelper', 'View/Helper');

class TimeHelper extends AppHelper
{
    /**
     * @param string|int $time
     * @return string
     */
    public function time($time)
    {
        if (empty($time)) {
            return '';
        }
        if (is_numeric($time)) {
            $time = date('Y-m-d H:i:s', $time);
        } else if (is_string($time)) { // time string with timezone
            $timezonePosition = strpos($time, '+00:00'); // first and last seen format
            if ($timezonePosition === false) {
                $timezonePosition = strpos($time, '+0000'); // datetime attribute format
            }
            if ($timezonePosition !== false) {
                return '<time title="' . __('In UTC') . '">' . h(substr($time, 0, $timezonePosition)) . '</time>';
            }
        }

        return '<time>' . h($time) . '</time>';
    }
}
