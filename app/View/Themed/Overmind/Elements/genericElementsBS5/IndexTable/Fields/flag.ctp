<?php
$country_value = is_array($row) ? Hash::get($row, $field['data_path']) : '';
if (is_array($country_value)) {
    $country_value = reset($country_value); 
}
$country = is_string($country_value) ? strtolower($country_value) : '';

// Map country codes to names and acronyms
$countries = [
    'us' => ['name' => 'United States', 'acronym' => 'USA'],
    'fr' => ['name' => 'France', 'acronym' => 'FR'],
    'de' => ['name' => 'Germany', 'acronym' => 'DE'],
    'gb' => ['name' => 'United Kingdom', 'acronym' => 'GB'],
    'eu' => ['name' => 'Europe', 'acronym' => 'EU'],
];

$country_name = isset($countries[$country]) ? $countries[$country]['name'] : '';
$country_acronym = isset($countries[$country]) ? $countries[$country]['acronym'] : strtoupper($country);

echo sprintf(
    '<div class="d-flex align-items-center gap-2"><span class="fi fi-%s" style="font-size: 1.5em;"></span><span class="fs-5">%s (%s)</span></div>',
    h($country),
    h($country_name),
    h($country_acronym)
);