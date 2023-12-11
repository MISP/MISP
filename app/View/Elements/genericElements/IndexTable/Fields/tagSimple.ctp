<?php
$tag = Hash::get($row, $field['data_path']);
if (!empty($tag)) {
    echo $this->element(
            'tag',
            ['tag' => $tag]
        );
}