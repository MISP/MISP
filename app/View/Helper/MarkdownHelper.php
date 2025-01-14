<?php
App::uses('AppHelper', 'View/Helper');

class MarkdownHelper extends AppHelper
{
    private $Parsedown = null;

    public function __construct(View $View, $settings = [])
    {
        parent::__construct($View, $settings);
        $this->Parsedown = new Parsedown();
    }
    
    public function text($input)
    {
        return $this->Parsedown->text($input);
    }

    public function line($input)
    {
        return $this->Parsedown->line($input);
    }
}
