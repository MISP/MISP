<?php
    $random = RandomTool::random_str(true, 8);;
    $type = empty($data['type']) ? 'generic' : $data['type'];
    echo $this->element('genericElements/Configuration/Fields/' . $type . 'Field.ctp', ['data' => $field]);
