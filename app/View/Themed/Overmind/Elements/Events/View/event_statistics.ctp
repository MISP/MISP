<?php

$content = '
<p>TO IMPLEMENT</p>

';

echo $this->element('genericElementsBS5/Cards/card_info', [
    'title' => __('Statistics'),
    'icon' => 'chart-pie',
    'content' => $content
]);

