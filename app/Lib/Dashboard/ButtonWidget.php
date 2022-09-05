<?php

class ButtonWidget
{
    public $title = 'Button Widget';
    public $render = 'Button';
    public $width = 3;
    public $height = 2;
    public $cacheLifetime = false;
    public $autoRefreshDelay = false;
    public $params = array(
        'url' => 'URL (after base url) to redirect to',
        'text' => 'Text to display on the button'
    );
    public $description = 'Simple button to allow shortcuts';
    public $placeholder =
'{
    "url": "/events/index",
    "text": "Go to events"
}';

    public function handler($user, $options = array())
    {
        $data = array();
        if(isset($options['url'])) {
            $data['url'] = $options['url'];
        }
        if(isset($options['text'])) {
            $data['text'] = $options['text'];
        }

        return $data;
    }
}