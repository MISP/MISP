<?php
App::uses('AppHelper', 'View/Helper');

class MarkdownHelper extends AppHelper
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
