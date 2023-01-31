<?php
    $value = Cake\Utility\Hash::extract($data, $field['path']);
    $value = empty($value[0]) ? '' : $value[0];
    echo $this->element('/genericElements/key', ['value' => $value, 'description' => $description ?? null]);
?>
