<?php
if (!empty($field['path'])) {
    $value = Hash::extract($data, $field['path']);
} else {
    $value = $data;
}
echo $field['function']($value, $this);
