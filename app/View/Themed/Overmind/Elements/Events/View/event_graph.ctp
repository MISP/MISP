<?php

$content = '<div id="event-graph"></div>';

echo $this->element('genericElementsBS5/Cards/card_info', [
    'title' => __('Correlation graph'),
    'icon' => 'project-diagram',
    'content' => $content
]);