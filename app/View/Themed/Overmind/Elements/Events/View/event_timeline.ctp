<?php

$content = '<div id="event-timeline"></div>';

echo $this->element('genericElementsBS5/Cards/card_info', [
    'title' => __('Timeline'),
    'icon' => 'clock',
    'content' => $content
]);