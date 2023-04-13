<?php
    echo $this->element(
        h($field['element']),
        empty($field['element_params']) ? [] : $field['element_params']
    );
