<?php
App::uses('AppHelper', 'View/Helper');

class TimeHelper extends AppHelper
{
    public function time($time)
    {
        if (empty($time)) {
            return '';
        }
        if (is_numeric($time)) {
            $time = date('Y-m-d H:i:s', $time);
        }

        $time = h($time);
        return '<time>' . $time . '</time>';
    }
}
