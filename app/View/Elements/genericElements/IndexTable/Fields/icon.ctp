<?php
echo sprintf(
    '<i class="black %s"></i>',
    h($this->FontAwesome->getClass(Hash::extract($row, $field['data_path'])[0]))
);