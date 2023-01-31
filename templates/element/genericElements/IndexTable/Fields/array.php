<?php
    $data = $this->Hash->extract($row, $field['data_path']);;
    if (!empty($field['isJson'])) {
        $data = json_decode($data[0], true);
    }
    echo $this->PrettyPrint->ppArray($data);
?>
