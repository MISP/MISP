<?php
$opinion = Hash::get($data, $field['path']);

echo $this->element('genericElements/Analyst_data/opinion_scale', [
    'opinion' => $opinion,
    'forceInline' => true,
]);
