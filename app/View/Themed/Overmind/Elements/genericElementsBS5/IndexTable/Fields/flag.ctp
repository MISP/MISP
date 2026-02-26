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
$country_flag = $this->Icon->countryFlag($country);

echo sprintf(
    '<div class="d-flex align-items-center gap-2">%s<span>%s (%s)</span></div>',
    $country_flag,
    h($country_name),
    h($country_acronym)
);