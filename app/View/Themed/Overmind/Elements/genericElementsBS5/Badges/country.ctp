<?php
/*
 * Expected:
 * $country (list of string)
 */

$countryList = isset($country) ? (is_array($country) ? $country : [$country]) : [];

// Map country codes to names and acronyms
$countries = [
    'us' => ['name' => 'United States', 'acronym' => 'USA'],
    'fr' => ['name' => 'France', 'acronym' => 'FR'],
    'de' => ['name' => 'Germany', 'acronym' => 'DE'],
    'gb' => ['name' => 'United Kingdom', 'acronym' => 'GB'],
    'eu' => ['name' => 'Europe', 'acronym' => 'EU'],
];

?>


<div class="d-flex flex-wrap gap-2">
    <?php foreach ($countryList as $c): ?>
        <?php 
            $c_code = strtolower($c);
            $country_info = $countries[$c_code] ?? null;
            $country_name = $country_info['name'] ?? ucfirst($c_code);
            $country_acronym = $country_info['acronym'] ?? strtoupper($c_code);
            $country_flag = $this->Icon->countryFlag($c_code);
        ?>
        <div class="d-inline-flex align-items-center gap-2">
            <?= $country_flag ?>
            <span class="fw-medium">
                <?= h($country_name) ?> <span class="text-muted text-uppercase">(<?= h($country_acronym) ?>)</span>
            </span>
        </div>
    <?php endforeach; ?>

    <?php if (empty($countryList)): ?>
        <span class="text-muted small italic"><?= __('No country specified') ?></span>
    <?php endif; ?>
</div>