<?php

$content = '<div id="event-timeline"></div>';

echo $this->element('genericElementsBS5/cards/info_card', [
    'title' => __('Timeline'),
    'icon' => 'clock',
    'content' => $content
]);