<?php
$attribute = Hash::get($row, $field['data_path']);
$attribute['objectType'] = 'attribute';
echo $this->element('Events/View/value_field', ['object' => $attribute]);
