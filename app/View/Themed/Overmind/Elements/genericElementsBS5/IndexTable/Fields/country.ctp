<?php
/*
 * country.ctp
 *
 * Expected:
 * $data_path => item.geographical_area'
 */

$country = Hash::extract($row, $field['data_path']);

if (empty($country)) {
    return;
}

echo $this->element(
    'genericElementsBS5/Badges/country',
    [
        'country' => $country,
    ]
);
?>