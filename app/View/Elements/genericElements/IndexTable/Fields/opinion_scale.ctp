<?php
    $opinion = Hash::get($row, $field['data_path']);

    echo $this->element('genericElements/Analyst_data/opinion_scale', [
        'opinion' => $opinion,
    ]);
