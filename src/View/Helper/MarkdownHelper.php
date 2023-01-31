<?php

namespace App\View\Helper;

use Cake\View\Helper;
use Cake\Utility\Hash;

class MarkdownHelper extends Helper
{
    private $Parsedown = null;

    public function text($input)
    {
        return $this->Parsedown->text($input);
    }

    public function line($input)
    {
        return $this->Parsedown->line($input);
    }
}
