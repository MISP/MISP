<?php
    $data = $this->Hash->get($row, $field['data_path']);
    if (is_null($data)) {
        echo '';
    } else if (!empty($data['require_update'])) {
        echo sprintf(
            '<span data-bs-toggle="tooltip" data-bs-title="%s">%s</span>',
            sprintf('Fields having differences: %s', (implode(', ', array_keys($data['differences'])))),
           $this->Bootstrap->icon('times', ['class' => 'text-danger', ])
        );
    } else {
        echo $this->Bootstrap->icon('check', ['class' => 'text-success',]);
    }
?>
