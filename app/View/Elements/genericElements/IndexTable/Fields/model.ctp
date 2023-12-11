<?php
$data = Hash::extract($row, $field['data_path']);
echo h($data['model']) . ' #' . intval($data['model_id']);
