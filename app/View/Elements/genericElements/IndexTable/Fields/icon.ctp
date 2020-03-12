<?php
echo sprintf(
    '<i class="black %s"></i>',
    $this->FontAwesome->getClass(Hash::extract($row, $field['data_path'])[0])
);