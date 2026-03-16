<?php

$content = '<div id="event-graph"></div>';

echo $this->element('genericElementsBS5/cards/info_card', [
    'title' => __('Correlation graph'),
    'icon' => 'project-diagram',
    'content' => $content
]);