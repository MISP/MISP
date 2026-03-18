<?php

$content = '
<p><strong>'.__('Event ID').'</strong><br>
'.h($data['Event']['id']).'</p>

<p><strong>'.__('UUID').'</strong><br>
'.h($data['Event']['uuid']).'</p>

<p><strong>'.__('Threat Level').'</strong><br>
'.h($data['ThreatLevel']['name']).'</p>

<p><strong>'.__('Analysis').'</strong><br>
'.h($data['Event']['analysis']).'</p>

<p><strong>'.__('Distribution').'</strong><br>
'.h($data['Event']['distribution']).'</p>

<p><strong>'.__('Published').'</strong><br>
'.h($data['Event']['published'] ? "Yes" : "No").'</p>

<p><strong>'.__('Date').'</strong><br>
'.h($data['Event']['date']).'</p>

<p><strong>'.__('Creator organisation').'</strong><br>
'.h($data['Orgc']['name']).'</p>

<p><strong>'.__('Owner organisation').'</strong><br>
'.h($data['Org']['name']).'</p>

<p><strong>'.__('Last update').'</strong><br>
'.$this->Time->time($data['Event']['timestamp']).'</p>

';

echo $this->element('genericElementsBS5/Cards/card_info', [
    'title' => __('General information'),
    'icon' => 'info-circle',
    'content' => $content
]);

