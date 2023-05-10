<?php
if (!empty($field['path'])) {
    $value = Cake\Utility\Hash::extract($data, $field['path']);
} else {
    $value = $data;
}
echo $field['function']($value, $this);
