<?php
App::uses('AppHelper', 'View/Helper');

class HashHelper extends AppHelper
{
    public function extract($target, $extraction_string)
    {
        return Hash::extract($target, $extraction_string);
    }

    public function get($target, $extraction_string)
    {
        return Hash::get($target, $extraction_string);
    }
}
