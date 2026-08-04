<?php
    $time = Hash::extract($row, $field['data_path'])[0];
    echo $this->Time->time($time);