<?php

App::uses('DashboardURLValidator', 'Lib/Dashboard/Tools');

class ButtonWidget
{
    public $title = 'Button Widget';
    public $category = 'custom';
    public $render = 'Button';
    public $width = 3;
    public $height = 2;
    public $cacheLifetime = false;
    public $autoRefreshDelay = false;
    public $params = array(
        'url' => 'URL (after base url) to redirect to',
        'text' => 'Text to display on the button'
    );
    public $schema = array();
    public $description = 'Simple button to allow shortcuts';
    public $placeholder =
'{
    "url": "/events/index",
    "text": "Go to events"
}';

    public function handler($user, $options = array())
    {
        $data = array();
        // `url` is raw widget config — the only fully attacker-supplied
        // URL on the dashboard. Gate it here as well as in the renderer
        // so an unsafe value never leaves the widget, whatever consumes
        // the payload (Button.ctp, the REST render, a future caller).
        // A dropped URL leaves `url` unset, which the renderer already
        // degrades to its inert "(Invalid URL)" tile.
        if (isset($options['url'])) {
            $safeUrl = DashboardURLValidator::validate((string)$options['url']);
            if ($safeUrl !== null) {
                $data['url'] = $safeUrl;
            }
        }
        if (isset($options['text'])) {
            $data['text'] = $options['text'];
        }

        return $data;
    }
}