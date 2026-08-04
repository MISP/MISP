<?php
if (!empty($field['data_path'])) {
    $data = Hash::extract($row, $field['data_path']);
    if (isset($data['model_id'])) {
        echo h($data['model']) . ' #' . intval($data['model_id']);
    }
} else {
    $model_name = Hash::extract($row, $field['model_name'])[0];
    $model_path = Inflector::Pluralize($model_name);
    $model_id = Hash::extract($row, $field['model_id'])[0];
    echo sprintf(
        '<a href="%s/%s/view/%s">%s (%s)</a>',
        $baseurl,
        h($model_path),
        h($model_id),
        h($model_name),
        h($model_id)
    );

}


