<?php
    $tags = $this->Hash->extract($row, $field['data_path']);
    echo $this->Tag->tags($tags, [
        'tags'
    ]);
