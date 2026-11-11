<?php
/*
 * A single attribute row, fetched on its own.
 */
echo $this->element(
    'Objects/object_add_attributes',
    [
        'element'     => $element,
        'k'           => $k,
        'appendValue' => '0',
    ]
);
