<?php

$content = '<div id="event-reports"></div>';

echo $this->element('genericElementsBS5/Cards/card_info', [
    'title' => __('Reports'),
    'icon' => 'file-alt',
    'content' => $content
]);