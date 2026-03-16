<?php

$content = '<div id="event-reports"></div>';

echo $this->element('genericElementsBS5/cards/info_card', [
    'title' => __('Reports'),
    'icon' => 'file-alt',
    'content' => $content
]);