<?php
    $value = Cake\Utility\Hash::extract($entity, $field['path']);
    $value = empty($value[0]) ? '' : $value[0];
    echo $this->element('/genericElements/key', ['value' => $value, 'description' => $description ?? null]);
?>
