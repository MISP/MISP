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
    // Typed contract for the two config keys. `url` is the only fully
    // attacker-supplied URL on the dashboard, so it declares the `url`
    // type and is therefore refused at save time by
    // CanonicalTypeAdapter::validate() as well as being gated in
    // handler() and in the renderer. Neither entry carries a `default`:
    // default injection would put a key into config that is absent
    // today, and handler() already degrades a missing key to the inert
    // "(Invalid URL)" tile.
    public $schema = array(
        'url' => array(
            'type' => 'url',
            'help' => 'Where the button goes. An absolute path on this '
                . 'instance, such as "/events/index".',
        ),
        'text' => array(
            'type' => 'string',
            'help' => 'Label shown on the button.',
        ),
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