<?php
// You can count on me. Raiders roll.
class CountExport
{
    public $additional_params = array(
        'flatten' => 1
    );
    private $__count = 0;
    public $non_restrictive_export = true;

    public function handler($data, $options = array())
    {
        if ($options['scope'] === 'Attribute') {
            $this->__count++;
        }
        if ($options['scope'] === 'Event') {
            $this->__count++;
        }
        return '';
    }

    public function header($options = array())
    {
        return '';
    }

    public function footer()
    {
        return $this->__count;
    }

    public function separator()
    {
        return "";
    }
}
