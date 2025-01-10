<?php
echo sprintf(
    '<i class="%s"></i>',
    $this->FontAwesome->getClass($this->Hash->extract($row, $field['data_path'])[0])
);
