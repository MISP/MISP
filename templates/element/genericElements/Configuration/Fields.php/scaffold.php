<?php
    $random = Cake\Utility\Security::randomString(8);
    $type = empty($data['type']) ? 'generic' : $data['type'];
    echo $this->element('genericElements/Configuration/Fields/' . $type . 'Field.php', ['data' => $field]);
