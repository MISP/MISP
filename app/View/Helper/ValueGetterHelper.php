<?php
App::uses('AppHelper', 'View/Helper');

class ValueGetterHelper extends AppHelper
{
    public function get($target, $args=[])
    {
        $value = '';
        if (is_callable($target)) {
            $value = $this->eval($target, $args);
        } else {
            $value = h($target);
        }
        return $value;
    }

    private function eval($fun, $args=[])
    {
        return $fun($args);
    }
}