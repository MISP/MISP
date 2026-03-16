<?php

$content = '
<p>TO IMPLEMENT</p>

';

echo $this->element('genericElementsBS5/cards/info_card', [
    'title' => __('General information'),
    'icon' => 'info-circle',
    'content' => $content
]);

