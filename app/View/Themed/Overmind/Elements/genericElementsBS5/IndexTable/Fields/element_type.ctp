<?php
/*
 * The kind of MISP record a row is — Event, GalaxyCluster, Attribute,
 * Object, Value — with its icon and colour.
 *
 * Expected:
 * $field['data_path'] => path to the type string
 */

$type = Hash::get($row, $field['data_path']);

if ($type === null || $type === '') {
    return;
}

echo $this->ElementType->badge($type);
